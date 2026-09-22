/**
 * NetHunterSOC Phase 2 Sample Telemetry Fixtures
 * For verification, rapid analyst onboarding, and deterministic testing.
 */

export const SAMPLE_CSV_TELEMETRY = `timestamp,src_ip,src_port,dst_ip,dst_port,protocol,packets,bytes,bytes_in,bytes_out,tcp_flags,connection_state,application_protocol,dns_query
2026-09-21T08:15:00.120Z,192.168.1.105,49231,1.1.1.1,53,UDP,2,148,82,66,,,dns,api.github.com
2026-09-21T08:15:00.180Z,192.168.1.105,51204,140.82.121.4,443,TCP,18,3420,2400,1020,ACK,ESTABLISHED,tls,
2026-09-21T08:15:02.340Z,192.168.1.105,51206,140.82.121.4,443,TCP,42,12500,10200,2300,FIN,CLOSED,tls,
2026-09-21T08:15:05.010Z,10.0.4.22,39844,10.0.4.1,22,TCP,34,4820,2210,2610,PSH,ESTABLISHED,ssh,
2026-09-21T08:15:10.500Z,192.168.1.50,55102,8.8.8.8,53,UDP,2,164,96,68,,,dns,update.internal.corp
2026-09-21T08:15:12.770Z,192.168.1.50,61230,198.51.100.45,80,TCP,8,1240,840,400,ACK,ESTABLISHED,http,
2026-09-21T08:15:15.900Z,10.0.2.14,48122,10.0.2.1,1,ICMP,4,256,128,128,,,ECHO_REPLY,,
2026-09-21T08:15:20.100Z,172.16.10.88,44219,10.0.0.53,53,UDP,2,180,100,80,,,dns,soc.defence.gov
2026-09-21T08:15:22.400Z,172.16.10.88,52119,185.199.108.153,443,TCP,24,6800,4200,2600,ACK,ESTABLISHED,tls,
2026-09-21T08:15:25.000Z,999.999.1.1,1234,10.0.0.1,80,TCP,1,64,0,64,SYN,SYN_SENT,,
2026-09-21T08:15:28.140Z,192.168.1.150,58922,192.168.1.1,443,TCP,12,2100,1200,900,ACK,ESTABLISHED,tls,
2026-09-21T08:15:30.650Z,192.168.1.150,58924,93.184.216.34,80,TCP,15,3100,2100,1000,ACK,ESTABLISHED,http,example.com
`;

export const SAMPLE_EVE_JSON_TELEMETRY = `{"timestamp":"2026-09-21T08:30:00.001Z","flow_id":1001,"event_type":"flow","src_ip":"192.168.1.200","src_port":54321,"dest_ip":"10.0.0.15","dest_port":80,"proto":"TCP","app_proto":"http","flow":{"pkts_toserver":12,"pkts_toclient":18,"bytes_toserver":1450,"bytes_toclient":4200,"start":"2026-09-21T08:29:55.000Z","end":"2026-09-21T08:30:00.000Z","age":5,"state":"closed","reason":"shutdown"}}
{"timestamp":"2026-09-21T08:30:01.120Z","flow_id":1002,"event_type":"dns","src_ip":"192.168.1.200","src_port":51120,"dest_ip":"1.1.1.1","dest_port":53,"proto":"UDP","dns":{"type":"query","id":4210,"rrname":"telemetry.soc-workbench.local","rrtype":"A","rcode":"NOERROR"}}
{"timestamp":"2026-09-21T08:30:02.450Z","flow_id":1003,"event_type":"alert","src_ip":"203.0.113.88","src_port":44321,"dest_ip":"192.168.1.20","dest_port":22,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":2001219,"rev":2,"signature":"ET SCAN Potential SSH Scan Connection Attempt","category":"Attempted Information Leak","severity":2}}
{"timestamp":"2026-09-21T08:30:03.010Z","flow_id":1004,"event_type":"flow","src_ip":"10.0.1.50","src_port":41200,"dest_ip":"10.0.1.1","dest_port":443,"proto":"TCP","app_proto":"tls","flow":{"pkts_toserver":25,"pkts_toclient":30,"bytes_toserver":3800,"bytes_toclient":8900,"state":"established"}}
{"timestamp":"2026-09-21T08:30:04.500Z","flow_id":1005,"event_type":"alert","src_ip":"198.51.100.77","src_port":60111,"dest_ip":"192.168.1.5","dest_port":8080,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":2014819,"rev":1,"signature":"ET WEB_SERVER Possible Path Traversal Sequence Observed","category":"Web Application Attack","severity":1}}
{"timestamp":"2026-09-21T08:30:05.100Z","flow_id":1006,"event_type":"dns","src_ip":"10.0.1.50","src_port":59001,"dest_ip":"8.8.8.8","dest_port":53,"proto":"UDP","dns":{"type":"query","id":9981,"rrname":"mirror.internal.network","rrtype":"AAAA","rcode":"NOERROR"}}
{"timestamp":"2026-09-21T08:30:06.200Z","flow_id":1007,"event_type":"flow","src_ip":"192.168.1.200","src_port":58890,"dest_ip":"142.250.190.46","dest_port":443,"proto":"TCP","app_proto":"tls","flow":{"pkts_toserver":8,"pkts_toclient":14,"bytes_toserver":980,"bytes_toclient":2100,"state":"closed"}}
MALFORMED_JSON_LINE_TEST_ERROR_RECOVERY
{"timestamp":"2026-09-21T08:30:08.750Z","flow_id":1008,"event_type":"flow","src_ip":"172.16.2.14","src_port":34110,"dest_ip":"172.16.2.1","dest_port":53,"proto":"UDP","app_proto":"dns","flow":{"pkts_toserver":2,"pkts_toclient":2,"bytes_toserver":140,"bytes_toclient":180,"state":"closed"}}
`;
