//GCC-TRUNK

#include "config.h"
#include "system.h"
#include "coretypes.h"
#include "tree.h"
#include "function.h"
#include "basic-block.h"
#include "gimple.h"
#include "options.h"
#include "diagnostic-path.h"
#include "diagnostic-metadata.h"
#include "function.h"
#include "json.h"
#include "analyzer/analyzer.h"
#include "diagnostic-event-id.h"
#include "analyzer/analyzer-logging.h"
#include "analyzer/sm.h"
#include "analyzer/pending-diagnostic.h"
#include "analyzer/function-set.h"
#include "analyzer/analyzer-selftests.h"
#include "tristate.h"
#include "selftest.h"
#include "analyzer/call-string.h"
#include "analyzer/program-point.h"
#include "analyzer/store.h"
#include "analyzer/region-model.h"


#if ENABLE_ANALYZER

namespace ana {
namespace {

class fd_state_machine : public state_machine
{
public:
	fd_state_machine (logger *logger);
	
	bool inherited_state_p () const FINAL OVERRIDE { return false; }
	
	state_machine::state_t
  get_default_state (const svalue *sval) const FINAL OVERRIDE
  {
    if (tree cst = sval->maybe_get_constant ())
      {
	if (zerop (cst))
	  return m_null;
      }
    return m_start;
  }
  
  bool on_stmt (sm_context *sm_ctxt,
		const supernode *node,
		const gimple *stmt) const FINAL OVERRIDE;

  void on_condition (sm_context *sm_ctxt,
				     const supernode *node,
				     const gimple *stmt,
				     const svalue *lhs,
				     enum tree_code op,
				     const svalue *rhs) const FINAL OVERRIDE;


  bool can_purge_p (state_t s) const FINAL OVERRIDE;
  pending_diagnostic *on_leak (tree var) const FINAL OVERRIDE;
  
  state_t m_unchecked;
  
  state_t m_closed;
  
  state_t m_stop;
  
  state_t m_file_leak;
  
  state_t m_null;
  
  state_t m_non_zero;
  
};


class fd_double_close_diagnostic : public pending_diagnostic_subclass<fd_double_close_diagnostic>
{
public:
 fd_double_close_diagnostic (const fd_state_machine &sm, tree arg) : m_sm (sm), m_arg (arg) {}
 
 
  const char *get_kind () const FINAL OVERRIDE { return "double close on fd"; }
	int get_controlling_option () const FINAL OVERRIDE
	{
    return OPT_Wanalyzer_double_fclose;
	}
  bool emit (rich_location *rich_loc) FINAL OVERRIDE
  {
	  
    return warning_at (rich_loc, OPT_Wanalyzer_double_fclose,
		       "double close on fd",
		       m_arg);
  }
  
  bool operator== (const fd_double_close_diagnostic &other) const
  {
    return same_tree_p (m_arg, other.m_arg);
  }
  
  label_text describe_state_change (const evdesc::state_change &change)
  OVERRIDE
  {
	  if (change.m_old_state == m_sm.get_start_state() && change.m_new_state == m_sm.m_unchecked)
	  {
		  return change.formatted_print ("opened here");
	  }
	  if (change.m_new_state == m_sm.m_closed)
	  {
		  m_first_fclose_event = change.m_event_id;
		  
		  return change.formatted_print ("first %qs here", "close");
	  }
	  
	  return label_text();
  }
  
  label_text describe_final_event (const evdesc::final_event &ev)
  FINAL OVERRIDE
  {
	if(m_first_fclose_event.known_p())
	{
		return ev.formatted_print ("second %qs was here; first %qs was at %@", "close", "close", &m_first_fclose_event);
	}
	return ev.formatted_print ("second %qs was here", "fclose");
  }
  
protected:
diagnostic_event_id_t m_first_fclose_event;
const fd_state_machine &m_sm;
tree m_arg;
};





class op_on_closed_fd_diagnostic : public pending_diagnostic_subclass<op_on_closed_fd_diagnostic>
{
public:
 op_on_closed_fd_diagnostic (const fd_state_machine &sm, tree arg, const char *name) : m_sm (sm), m_arg (arg), m_name(name) {}
 
 int get_controlling_option () const FINAL OVERRIDE
  {
    return 1;
  }
  const char *get_kind () const FINAL OVERRIDE { return "op on closed fd"; }

  bool emit (rich_location *rich_loc) FINAL OVERRIDE
  {
	 
    return warning_at (rich_loc, OPT_Wanalyzer_double_fclose,
		       "%s on closed fd", m_name,
		       m_arg);
  }
  
  bool operator== (const op_on_closed_fd_diagnostic &other) const
  {
    return same_tree_p (m_arg, other.m_arg);
  }
	
  label_text describe_state_change (const evdesc::state_change &change)
  OVERRIDE
  {
	  if (change.m_old_state == m_sm.get_start_state() && change.m_new_state == m_sm.m_unchecked)
	  {
		  return change.formatted_print ("opened here");
	  }
	  if (change.m_new_state == m_sm.m_closed)
	  {
		  m_first_fclose_event = change.m_event_id;
		  
		  return change.formatted_print ("first %qs here", "close");
	  }
	  
	  
	  return label_text();
  }
  
  label_text describe_final_event (const evdesc::final_event &ev)
  FINAL OVERRIDE
  {
	if(m_first_fclose_event.known_p())
	{
		return ev.formatted_print ("%s on closed file-descriptor %qE was called here which was closed at %@",m_name,  m_arg, &m_first_fclose_event);
	}
	return ev.formatted_print ("%s on closed file-descriptor was called here", m_name);
  }
  
  

protected:
diagnostic_event_id_t m_first_fclose_event;
const fd_state_machine &m_sm;
tree m_arg;
const char * m_name;
};

class fd_leak : public pending_diagnostic_subclass <fd_leak>
{
public:
 fd_leak (const fd_state_machine &sm, tree arg, bool leak_by_not_saving) : m_sm (sm), m_arg (arg), m_leak_by_not_saving(leak_by_not_saving) {}
 
 int get_controlling_option () const FINAL OVERRIDE
  {
    return OPT_Wanalyzer_file_leak;
  }
  
 const char *get_kind () const FINAL OVERRIDE
  {
    return "fd leak";
  }
  
  
  bool operator== (const fd_leak &other) const
  {
    return true;
  }
  
  bool emit (rich_location *rich_loc) FINAL OVERRIDE
  {
    diagnostic_metadata m;
    /* CWE-775: "Missing Release of File Descriptor or Handle after
       Effective Lifetime". */
    m.add_cwe (775);
	if (m_leak_by_not_saving)
	return warning_meta (rich_loc, m, OPT_Wanalyzer_file_leak, "leak by not saving fd");
    return warning_meta (rich_loc, m, OPT_Wanalyzer_file_leak,
			 "leak of FILE %qE",
			 m_arg);
  }
  
  
  label_text describe_state_change (const evdesc::state_change &change)
  OVERRIDE
  {
	  if (change.m_old_state == m_sm.get_start_state() && change.m_new_state == m_sm.m_unchecked)
	  {
		  return change.formatted_print ("opened here");
	  }
	  
	 
	 
	  return label_text();
  }
  
  label_text describe_final_event (const evdesc::final_event &ev)
  FINAL OVERRIDE
  {
	   if (m_leak_by_not_saving) 
	  {
		  return ev.formatted_print ("leak by not saving fd");
	  }
	
	return ev.formatted_print ("leaks here");
  }
  
  
  
  
 
protected:
diagnostic_event_id_t m_open_event;
const fd_state_machine &m_sm;
tree m_arg;
bool m_leak_by_not_saving;
};



fd_state_machine::fd_state_machine (logger *logger)
: state_machine ("posix-fd", logger)
{
	m_unchecked = add_state ("fd-unchecked");
	m_closed = add_state ("fd-closed");
	m_stop = add_state ("fd-stop");
	m_null = add_state ("fd-null");
	m_file_leak = add_state ("m_file_leak");
	m_non_zero = add_state ("non-zero");
	
}

bool fd_state_machine::on_stmt (sm_context *sm_ctxt,
		const supernode *node,
		const gimple *stmt) const
{
	if (const gcall *call = dyn_cast <const gcall *> (stmt))
		if (tree callee_fndecl = sm_ctxt->get_fndecl_for_call (call))
		{
			if(is_named_call_p (callee_fndecl, "open", call, 2))
			{
				tree lhs = gimple_call_lhs (call);
				if(lhs)
					sm_ctxt->on_transition (node, stmt, lhs, m_start, m_unchecked);
				else {
					tree arg = gimple_call_fn (call);
					sm_ctxt->set_next_state (stmt, arg, m_file_leak);
					tree diag_arg = sm_ctxt->get_diagnostic_tree (arg);
					sm_ctxt->warn (node, stmt, arg, new fd_leak(*this, diag_arg, true));
				}
				return true;
			}
			
			if (is_named_call_p(callee_fndecl, "close", call, 1))
			{
				tree arg = gimple_call_arg (call, 0);
				
				sm_ctxt->on_transition(node, stmt, arg, m_unchecked, m_closed);
				sm_ctxt->on_transition(node, stmt, arg, m_null, m_closed);
				sm_ctxt->on_transition(node, stmt, arg, m_non_zero, m_closed);
				if (sm_ctxt->get_state (stmt, arg) == m_closed)
				{
					tree diag_arg = sm_ctxt->get_diagnostic_tree (arg);
					sm_ctxt->warn (node, stmt, arg, new fd_double_close_diagnostic (*this, diag_arg));
					//sm_ctxt->set_next_state (stmt, arg, m_stop);
				}
				return true;
			}
			
			if (is_named_call_p (callee_fndecl, "dup", call, 1))
			{
				tree arg = gimple_call_arg (call, 0);
				if(sm_ctxt->get_state (stmt, arg) == m_closed || sm_ctxt->get_state (stmt, arg) == m_stop)
				{
					tree diag_arg = sm_ctxt->get_diagnostic_tree (arg);
					sm_ctxt->warn (node, stmt, arg, new op_on_closed_fd_diagnostic (*this, diag_arg, "dup"));
					//sm_ctxt->set_next_state(stmt, arg, m_stop);
				}
				else
				{
				tree lhs = gimple_call_lhs(call);
				if(lhs)
					sm_ctxt->on_transition(node, stmt, lhs, m_start, m_unchecked);
				}
				return true;
			}
			
			if (is_named_call_p (callee_fndecl, "write", call, 3))
			{
				
				tree arg = gimple_call_arg(call, 0);
				if (sm_ctxt->get_state (stmt, arg) == m_closed)
				{
					tree diag_tree = sm_ctxt->get_diagnostic_tree (arg);
					sm_ctxt->warn (node, stmt, arg, new op_on_closed_fd_diagnostic (*this, diag_tree, "write"));
				}					
				return true;
			}
			
			if (is_named_call_p (callee_fndecl, "read", call, 3))
			{
				
				tree arg = gimple_call_arg(call, 0);
				if (sm_ctxt->get_state (stmt, arg) == m_closed)
				{
					tree diag_tree = sm_ctxt->get_diagnostic_tree (arg);
					sm_ctxt->warn (node, stmt, arg, new op_on_closed_fd_diagnostic (*this, diag_tree, "read"));
				}					
				return true;
			}
			
				
			
			
		}
		
		
		return false;
	
}



void
fd_state_machine::on_condition (sm_context *sm_ctxt,
				     const supernode *node,
				     const gimple *stmt,
				     const svalue *lhs,
				     enum tree_code op,
				     const svalue *rhs) const
{
	if(op == NE_EXPR) 
	{
		log ("got ARG != 0");
		sm_ctxt->on_transition (node, stmt, lhs, m_unchecked, m_non_zero);
	}
	else if (op == EQ_EXPR)
	{
		log ("got ARG == 0");
		sm_ctxt->on_transition (node, stmt, lhs, m_unchecked, m_null);
	}
}

bool fd_state_machine::can_purge_p (state_t state) const {
	return state != m_unchecked && state != m_non_zero;
}


pending_diagnostic*
fd_state_machine::on_leak (tree var) const
{
	return new fd_leak (*this, var, false);
} 

}

state_machine*
make_fd_state_machine (logger *logger)
{
	return new fd_state_machine (logger);
}

}

#endif