import 'package:flutter_test/flutter_test.dart';

import 'package:jeesite_des/jeesite_des.dart';

void main() {
  test('desEncode', () {
    var desResult = JeesiteDesUtils.encode('system', 'thinkgem,jeesite,com');
    expect(desResult, 'F3EDC7D2C193E0B8DCF554C726719ED2');
  });
}
