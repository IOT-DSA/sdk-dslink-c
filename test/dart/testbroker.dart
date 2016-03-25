import "package:dslink/dslink.dart";
import "package:dslink/utils.dart" show BinaryData, ByteDataUtil, DsTimer;
import "package:test/test.dart";
import 'package:uuid/uuid.dart';

import "dart:math" as Math;
import 'dart:typed_data';
import 'dart:async';

LinkProvider responder;
LinkProvider requester;

var uuid = new Uuid();
final String brokerUrl = 'localhost:8100/conn';

SimpleNodeProvider createSimpleNodeProvider({Map nodes, Map profiles}) {
  return new SimpleNodeProvider(nodes, profiles);
}

void main() {
  setUp(() async {
    var id = uuid.v1();

    responder = new LinkProvider(
        ['-b', brokerUrl, '--log', 'finest'], "resp1-${id}-", isResponder: true
    );

    requester = new LinkProvider(
        ['-b', brokerUrl, '--log', 'finest'], "req1-${id}-", isRequester: true
    );
  });

  tearDown(() async {

  });

  test("Requester gets update from nonexistent node", () async {
    {
      var num = new Math.Random().nextInt(500000);
      LinkProvider link = new LinkProvider(
          ['-b', brokerUrl, '--log', 'finest'], 'req1-',
          isRequester:true);
      link.connect();

      var req = await link.onRequesterReady;
      var future = req.onValueChange('/data/${num}').first;
      await new Future.delayed(const Duration(seconds: 2));
      req.set("/data/${num}", num);
      var val = await future;
      print("Expect ${num}, got ${val.value}");

      expect(val.value, isNotNull);
      expect(val.value, equals(num));
    }
  });
}