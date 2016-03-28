import "package:dslink/dslink.dart";
import "package:dslink/utils.dart" show BinaryData, ByteDataUtil, DsTimer;

import "dart:math" as Math;
import 'dart:typed_data';
import 'dart:async';


main(List<String> args) {
  var node;
  String brokerUrl = 'localhost:8100/conn';
  {
    LinkProvider link = new LinkProvider(
        ['-b', brokerUrl, '--log', 'finest'], 'resp1-',
        isResponder:true);
    
    node = link.provider.getOrCreateNode('/node', true);
    node.configs[r'$type'] = 'string';
    node.updateValue("v1");
    link.connect();
  }
  
  {
    LinkProvider link = new LinkProvider(
        ['-b', brokerUrl, '--log', 'finest'], 'req1-',
         isRequester:true);
    link.connect();
    link.onRequesterReady.then((req) async{
      var listener = req.subscribe('/downstream/resp1/node',(update){
        print('update received: ${update.value}');
      });
      await (new Future.delayed(new Duration(seconds:1)));
      node.updateValue("v2");
      node.updateValue("v3");
    });
  }
}
