def init_standard(id, env):
    return True

def deinit(id):
    return True

def inform_super(id, qstate, superqstate, qdata):
    return True

def operate(id, event, qstate, qdata):
    if event == MODULE_EVENT_NEW or event == MODULE_EVENT_PASS:
        msg = DNSMessage(qstate.qinfo.qname_str, qstate.qinfo.qtype, qstate.qinfo.qclass, PKT_QR | PKT_AA)
        msg.answer.append("helloworld. 300 IN A 127.0.0.1")
        msg.set_return_msg(qstate)
        qstate.return_rcode = RCODE_NOERROR
        qstate.return_msg.rep.security = 2
        qstate.ext_state[id] = MODULE_FINISHED
    elif event == MODULE_EVENT_MODDONE:
        qstate.ext_state[id] = MODULE_FINISHED
    else:
        qstate.ext_state[id] = MODULE_ERROR
    return True
