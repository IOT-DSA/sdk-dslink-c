import "package:dslink/dslink.dart";
import "package:dslink/utils.dart" show BinaryData, ByteDataUtil, DsTimer;

import "dart:math" as Math;
import 'dart:typed_data';
import 'dart:async';


class ActNode extends SimpleNode {
  ActNode(String path) : super(path); 
  InvokeResponse invoke(Map params, Responder responder,
        InvokeResponse response, LocalNode parentNode,
        [int maxPermission = Permission.CONFIG]) {
    response.updateStream(null, meta:{'mode':'append'}, streamStatus: StreamStatus.initialize);
    ()async{
      await new Future.delayed(new Duration(milliseconds: 200));
      response.updateStream([[1]]);
      await new Future.delayed(new Duration(milliseconds: 200));
      response.updateStream([[2]]);
    }();
    return response;
  }
}
Map profiles = {
  'act': (String path) => new ActNode(path)
};

main(List<String> args) {
  String brokerUrl = 'localhost:8100/conn';
  {
    Map defaultNodes = {
      'act':{
        r'$is':'act',
        r'$invokable':'read',
        r'$result' :'stream',
        r'$columns': [{'name':'a',"type": "string"}]
      }
    };
    
    LinkProvider link = new LinkProvider(
        ['-b', brokerUrl, '--log', 'finest'], 'resp1-',
        isResponder:true,defaultNodes: defaultNodes, profiles:profiles);
    link.connect();
  }
  
  {
    LinkProvider link = new LinkProvider(
        ['-b', brokerUrl, '--log', 'finest'], 'req1-',
         isRequester:true);
    link.connect();
    link.onRequesterReady.then((req) async{
      req.invoke('/downstream/resp1/act',{}).listen((var update){
        print('received ${update.rows}');
      });
    });
  }
}
