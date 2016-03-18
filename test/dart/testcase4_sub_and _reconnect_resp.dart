import "package:dslink/dslink.dart";
import "package:dslink/utils.dart" show BinaryData, ByteDataUtil, DsTimer;

import "dart:math" as Math;
import 'dart:typed_data';
import 'dart:async';


main(List<String> args) {
  String brokerUrl = 'localhost:8100/conn';
  LinkProvider resplink;
  int count = 1;
  void startRespLink(){
    resplink = new LinkProvider(
        ['-b', brokerUrl, '--log', 'finest'], 'resp1-',
        isResponder:true);
    
    var node = resplink.provider.getOrCreateNode('/node', true);
    node.configs[r'$type'] = 'string';
    node.updateValue("v${count++}");
    resplink.connect();
  }
  startRespLink();
  
  {
    LinkProvider link = new LinkProvider(
        ['-b', brokerUrl, '--log', 'finest'], 'req1-',
         isRequester:true);
    link.connect();
    link.onRequesterReady.then((req) {
      var listener = req.subscribe('/downstream/resp1/node',(update) async{
        print('update received: ${update.value}');
        if (resplink != null) {
          resplink.close();
          await (new Future.delayed(new Duration(seconds:1))); 
          // reconnect the responder
          startRespLink();
          // don't do it again
          resplink = null;
        }
      });
      
    });
  }
}
