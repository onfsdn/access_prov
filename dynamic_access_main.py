import json
import logging
import dynamic_access
from ryu.app import simple_switch_13
from webob import Response
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.app.wsgi import ControllerBase, WSGIApplication, route

#configure port and ip in sudo /usr/local/etc/ryu/ryu.conf
#uncomment wsapi_host=ip_addr,wsapi_port=port_no
#configure port and ip in sudo .ryu/app/dynamic_access.py
#_ipaddr='http://ip_addr:' ,_ipaddr_port=port_no

app_name='dynamicaccess'
LOG = logging.getLogger('DynamicAccessRest')
LOG.setLevel(logging.INFO)
logging.basicConfig()

url = '/'+app_name+'/test'
urldel = '/'+app_name+'/del'
url1 = '/'+app_name+'/serverconfig'
url2 = '/'+app_name+'/authenticateduser'
url3 = '/'+app_name+'/evictuser'

_sccess_status ={'status':'200'}
_failure_status={'status':500}

dynamic_switch = 'dynamic_switch_api_app'


class DynamicAccessRest(dynamic_access.Begin):
    _CONTEXTS = { 'wsgi': WSGIApplication }
    def __init__(self, *args, **kwargs):
        super(DynamicAccessRest, self).__init__(*args, **kwargs)                
        self.switches = {}
        wsgi = kwargs['wsgi']
        wsgi.register(DynamicController, {dynamic_switch : self})
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        super(DynamicAccessRest, self).switch_features_handler(ev)
        datapath = ev.msg.datapath
        self.switches[datapath.id] = datapath
        self.mac_to_port.setdefault(datapath.id, {})
        LOG.info("Switch list ",self.switches )
        
    def set_mac_to_port(self, dpid, entry):
        mac_table = self.mac_to_port.setdefault(dpid, {})
        datapath = self.switches.get(dpid)
        entry_port = entry['port']
        entry_mac = entry['mac']
        if datapath is not None:
            parser = datapath.ofproto_parser
            if entry_port not in mac_table.values():
                for mac, port in mac_table.items():
                    # from known device to new device
                    actions = [parser.OFPActionOutput(entry_port)]
                    match = parser.OFPMatch(in_port=port, eth_dst=entry_mac)
                    self.add_flow(datapath, 1, match, actions)
                    # from new device to known device
                    actions = [parser.OFPActionOutput(port)]
                    match = parser.OFPMatch(in_port=entry_port, eth_dst=mac)
                    self.add_flow(datapath, 1, match, actions)
                    mac_table.update({entry_mac : entry_port})
        return mac_table

class DynamicController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(DynamicController, self).__init__(req, link, data, **config)
        self.simpl_switch_spp = data[dynamic_switch]        
        
    @route(app_name, url, methods=['GET'])
    def test(self, req, **kwargs):
        simple_switch = self.simpl_switch_spp
        #new_entry = eval(req.body)
        dpid=1
        cookie=1
        cookie_mask=1
        table_id=1
        idle_timeout=1100
        hard_timeout=5000
        priority=2
        flags=1
        in_port=1
        type_type='OUTPUT'
        port=1
        simple_switch.add_redirect_flow_byrest(dpid,cookie,cookie_mask,table_id,idle_timeout,hard_timeout,priority,flags,in_port,type_type,port)
        body = json.dumps("GET")
        return Response(content_type='application/json', body=body)
    
    @route(app_name, urldel, methods=['GET'])
    def testdel(self, req, **kwargs):
        simple_switch = self.simpl_switch_spp
        #new_entry = eval(req.body)
        dpid=1
        cookie=1
        cookie_mask=1
        table_id=1
        idle_timeout=1100
        hard_timeout=5000
        priority=2
        flags=1
        in_port=1
        type_type='OUTPUT'
        port=1
        simple_switch.del_redirect_flow_byrest(dpid,cookie,cookie_mask,table_id,idle_timeout,hard_timeout,priority,flags,in_port,type_type,port)
        body = json.dumps("GET")
        return Response(content_type='application/json', body=body)
    
    #url1 = http:<ip-aadr>:<tcp_port>/dynamicaccess/serverconfig'
    #
    #
    @route(app_name, url1, methods=['POST'])
    def serverconfig(self, req, **kwargs):
        simple_switch = self.simpl_switch_spp
        LOG.info("connection request"+str(req))
        new_entry = eval(req.body)
        LOG.info("connection request for %s ",url1 )
        try:
            LOG.info("connection request for"+str(new_entry) )
            simple_switch.json_server_parse(new_entry)
            body = json.dumps(_sccess_status)
            return Response(content_type='application/json', body=body)
        except Exception as e:
            return Response(_failure_status)
    
    #url2 = http:<ip-aadr>:<tcp_port>/dynamicaccess/authenticateduser'
    @route(app_name, url2, methods=['POST'])
    def authenticateduser(self, req, **kwargs):
        simple_switch = self.simpl_switch_spp
        new_entry = eval(req.body)
        LOG.info("connection request for %s ",url2 )
        try:
            simple_switch.json_user_parse(new_entry)
            body = json.dumps(_sccess_status)
            return Response(content_type='application/json', body=body)
        except Exception as e:
            return Response(_failure_status)
    
    #url3 = http:<ip-aadr>:<tcp_port>/dynamicaccess/evictuser'
    @route(app_name, url3, methods=['POST'])
    def evictuser(self, req, **kwargs):
        simple_switch = self.simpl_switch_spp
        new_entry = eval(req.body)
        LOG.info("connection request for %s ",url3 )
        try:
            simple_switch.json_evict_parse(new_entry)
            body = json.dumps(_sccess_status)
            return Response(content_type='application/json', body=body)
        except Exception as e:
            return Response(_failure_status)    
    
