import "package:dslink/dslink.dart";
import "package:dslink/utils.dart" show BinaryData, ByteDataUtil, DsTimer;

import "dart:math" as Math;
import 'dart:typed_data';
import 'dart:async';


main(List<String> args) {
  String brokerUrl = 'localhost:8100/conn';
 
 {
    int count = 1;
    LinkProvider resplink = new LinkProvider(
        ['-b', brokerUrl, '--log', 'finest'], 'resp1-',
        isResponder:true);
    
    var node = resplink.provider.getOrCreateNode('/node', true);
    node.configs[r'$type'] = 'string';
    new Timer.periodic(new Duration(milliseconds:200),(t){
      node.updateValue("v${count++}");
    });
   
    resplink.connect();
  }
  LinkProvider reqLink;
  
  void startReqLink2(){
    LinkProvider reqLink = new LinkProvider(
        ['-b', brokerUrl, '--log', 'finest'], 'req1-',
         isRequester:true);
    reqLink.connect();
    reqLink.onRequesterReady.then((req) {
      var listener = req.subscribe('/downstream/resp1/node',(update) async{
        print('update2 received: ${update.value}');
      }, 3);
    });
  }
  void startReqLink(){
    reqLink = new LinkProvider(
        ['-b', brokerUrl, '--log', 'finest'], 'req1-',
         isRequester:true);
    reqLink.connect();
    reqLink.onRequesterReady.then((req) {
      var listener = req.subscribe('/downstream/resp1/node',(update) async{
        print('update received: ${update.value}');
        if (reqLink != null) {
          reqLink.close();
          await new Future.delayed(new Duration(seconds:2));
          startReqLink2();
        }
      }, 3);
    });
  }
  
  startReqLink();
}
