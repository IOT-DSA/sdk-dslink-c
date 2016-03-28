import "dart:async";
import "dart:math" as Math;

import "package:dslink/dslink.dart";

import "package:test/test.dart";

final String brokerUrl = "http://localhost:8100/conn";

void main() {
  test("Requester gets value update from nonexistent node", () async {
    {
      var num = new Math.Random().nextInt(500000);
      LinkProvider link = new LinkProvider(
        [
          "-b", brokerUrl,
          "--log", "finest"
        ],
        "req1-",
        isRequester: true
      );
      link.connect();

      var req = await link.onRequesterReady;
      var future = req.onValueChange("/data/${num}").first;
      await new Future.delayed(const Duration(seconds: 2));
      req.set("/data/${num}", num);
      var val = await future;

      expect(val.value, isNotNull);
      expect(val.value, equals(num));
      link.close();
    }
  });
}
