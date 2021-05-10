library jeesite_des;

class JeesiteDesUtils {

  static _DesCore _desCore = new _DesCore();

  /**
   * DES加密（secretKey代表3个key，用逗号分隔）
   */
  static String encode(String data, String secretKey) {
    if (data == "") {
      return "";
    }

    /*
		if ("Base64".equals(secretKey)) {
			return EncodeUtils.encodeBase64(data);
		}
		*/
    List<String> ks = secretKey.split(",");
    if (ks.length >= 3) {
      return _desCore.strEnc(data, ks[0], ks[1], ks[2]);
    }
    return _desCore.strEnc(data, secretKey, "", "");
  }

}

/**
 * DES加密/解密
 * @Copyright Copyright (c) 2006
 * @author Guapo
 */
class _DesCore {
  /*
		 * encrypt the string to string made up of hex return the encrypted string
		 */
  String strEnc(String data, String? firstKey, String? secondKey, String? thirdKey) {

    int leng = data.length;
    String encData = "";
    List<List<int>>? firstKeyBt = null, secondKeyBt = null, thirdKeyBt = null;
    int firstLength = 0, secondLength = 0, thirdLength = 0;
    if (firstKey != null && firstKey != "") {
      firstKeyBt = getKeyBytes(firstKey);
      firstLength = firstKeyBt.length;
    }
    if (secondKey != null && secondKey != "") {
      secondKeyBt = getKeyBytes(secondKey);
      secondLength = secondKeyBt.length;
    }
    if (thirdKey != null && thirdKey != "") {
      thirdKeyBt = getKeyBytes(thirdKey);
      thirdLength = thirdKeyBt.length;
    }

    if (leng > 0) {
      if (leng < 4) {
        List<int> bt = strToBt(data);
        List<int>? encByte = null;
        if (firstKey != null && firstKey != "" && secondKey != null && secondKey != "" && thirdKey != null && thirdKey != "") {
          List<int> tempBt;
          int x, y, z;
          tempBt = bt;
          for (x = 0; x < firstLength; x++) {
            tempBt = enc(tempBt, firstKeyBt!.elementAt(x));
          }
          for (y = 0; y < secondLength; y++) {
            tempBt = enc(tempBt, secondKeyBt!.elementAt(y));
          }
          for (z = 0; z < thirdLength; z++) {
            tempBt = enc(tempBt, thirdKeyBt!.elementAt(z));
          }
          encByte = tempBt;
        } else {
          if (firstKey != null && firstKey != "" && secondKey != null && secondKey != "") {
            List<int> tempBt;
            int x, y;
            tempBt = bt;
            for (x = 0; x < firstLength; x++) {
              tempBt = enc(tempBt, firstKeyBt!.elementAt(x));
            }
            for (y = 0; y < secondLength; y++) {
              tempBt = enc(tempBt, secondKeyBt!.elementAt(y));
            }
            encByte = tempBt;
          } else {
            if (firstKey != null && firstKey != "") {
              List<int> tempBt;
              int x = 0;
              tempBt = bt;
              for (x = 0; x < firstLength; x++) {
                tempBt = enc(tempBt, firstKeyBt!.elementAt(x));
              }
              encByte = tempBt;
            }
          }
        }
        encData = bt64ToHex(encByte!);
      } else {
        int iterator = (leng ~/ 4);
        int remainder = leng % 4;
        int i = 0;
        for (i = 0; i < iterator; i++) {
          String tempData = data.substring(i * 4 + 0, i * 4 + 4);
          List<int> tempByte = strToBt(tempData);
          List<int>? encByte = null;
          if (firstKey != null && firstKey != "" && secondKey != null && secondKey != "" && thirdKey != null && thirdKey != "") {
            List<int> tempBt;
            int x, y, z;
            tempBt = tempByte;
            for (x = 0; x < firstLength; x++) {
              tempBt = enc(tempBt, firstKeyBt!.elementAt(x));
            }
            for (y = 0; y < secondLength; y++) {
              tempBt = enc(tempBt, secondKeyBt!.elementAt(y));
            }
            for (z = 0; z < thirdLength; z++) {
              tempBt = enc(tempBt, thirdKeyBt!.elementAt(z));
            }
            encByte = tempBt;
          } else {
            if (firstKey != null && firstKey != "" && secondKey != null && secondKey != "") {
              List<int> tempBt;
              int x, y;
              tempBt = tempByte;
              for (x = 0; x < firstLength; x++) {
                tempBt = enc(tempBt, firstKeyBt!.elementAt(x));
              }
              for (y = 0; y < secondLength; y++) {
                tempBt = enc(tempBt, secondKeyBt!.elementAt(y));
              }
              encByte = tempBt;
            } else {
              if (firstKey != null && firstKey != "") {
                List<int> tempBt;
                int x;
                tempBt = tempByte;
                for (x = 0; x < firstLength; x++) {
                  tempBt = enc(tempBt, firstKeyBt!.elementAt(x));
                }
                encByte = tempBt;
              }
            }
          }
          encData += bt64ToHex(encByte!);
        }
        if (remainder > 0) {
          String remainderData = data.substring(iterator * 4 + 0, leng);
          List<int> tempByte = strToBt(remainderData);
          List<int>? encByte = null;
          if (firstKey != null && firstKey != "" && secondKey != null && secondKey != "" && thirdKey != null && thirdKey != "") {
            List<int> tempBt;
            int x, y, z;
            tempBt = tempByte;
            for (x = 0; x < firstLength; x++) {
              tempBt = enc(tempBt, firstKeyBt!.elementAt(x));
            }
            for (y = 0; y < secondLength; y++) {
              tempBt = enc(tempBt, secondKeyBt!.elementAt(y));
            }
            for (z = 0; z < thirdLength; z++) {
              tempBt = enc(tempBt, thirdKeyBt!.elementAt(z));
            }
            encByte = tempBt;
          } else {
            if (firstKey != null && firstKey != "" && secondKey != null && secondKey != "") {
              List<int> tempBt;
              int x, y;
              tempBt = tempByte;
              for (x = 0; x < firstLength; x++) {
                tempBt = enc(tempBt, firstKeyBt!.elementAt(x));
              }
              for (y = 0; y < secondLength; y++) {
                tempBt = enc(tempBt, secondKeyBt!.elementAt(y));
              }
              encByte = tempBt;
            } else {
              if (firstKey != null && firstKey != "") {
                List<int> tempBt;
                int x;
                tempBt = tempByte;
                for (x = 0; x < firstLength; x++) {
                  tempBt = enc(tempBt, firstKeyBt!.elementAt(x));
                }
                encByte = tempBt;
              }
            }
          }
          encData += bt64ToHex(encByte!);
        }
      }
    }
    return encData;
  }


  /*
		 * chang the string into the bit array
		 *
		 * return bit array(it's length % 64 = 0)
		 */
  List<List<int>> getKeyBytes(String key) {
    List<List<int>> keyBytes = [];
    int leng = key.length;
    int iterator = (leng ~/ 4);
    int remainder = leng % 4;
    int i = 0;
    for (i = 0; i < iterator; i++) {
      keyBytes.add(strToBt(key.substring(i * 4 + 0, i * 4 + 4)));
    }
    if (remainder > 0) {
      keyBytes.add(strToBt(key.substring(i * 4 + 0, leng)));
    }
    return keyBytes;
  }

  /*
		 * chang the string(it's length <= 4) into the bit array
		 *
		 * return bit array(it's length = 64)
		 */
  List<int> strToBt(String str) {
    int leng = str.length;
    List<int> bt = List<int>.filled(64, 0);
    if (leng < 4) {
      int i = 0, j = 0, p = 0, q = 0;
      for (i = 0; i < leng; i++) {
        int k = str.codeUnitAt(i);
        for (j = 0; j < 16; j++) {
          int pow = 1, m = 0;
          for (m = 15; m > j; m--) {
            pow *= 2;
          }
          // bt.set(16*i+j,""+(k/pow)%2));
          bt[16 * i + j] = (k ~/ pow) % 2;
        }
      }
      for (p = leng; p < 4; p++) {
        int k = 0;
        for (q = 0; q < 16; q++) {
          int pow = 1, m = 0;
          for (m = 15; m > q; m--) {
            pow *= 2;
          }
          // bt[16*p+q]=parseInt(k/pow)%2;
          // bt.add(16*p+q,""+((k/pow)%2));
          bt[16 * p + q] = (k ~/ pow) % 2;
        }
      }
    } else {
      for (int i = 0; i < 4; i++) {
        int k = str.codeUnitAt(i);
        for (int j = 0; j < 16; j++) {
          int pow = 1;
          for (int m = 15; m > j; m--) {
            pow *= 2;
          }
          // bt[16*i+j]=parseInt(k/pow)%2;
          // bt.add(16*i+j,""+((k/pow)%2));
          bt[16 * i + j] = (k ~/ pow) % 2;
        }
      }
    }
    return bt;
  }
  /*


		 * chang the bit(it's length = 4) into the hex
		 *
		 * return hex
		 */
  String bt4ToHex(String binary) {
    List<String> tbls = [
      "0000", "0001", "0010", "0011",
      "0100", "0101", "0110", "0111",
      "1000", "1001", "1010", "1011",
      "1100", "1101", "1110", "1111"
    ];
    int index = tbls.indexOf(binary);
    if (index == -1) return "";
    return "0123456789ABCDEF"[index];
  }


  /*
		 * chang the hex into the bit(it's length = 4)
		 *
		 * return the bit(it's length = 4)
		 */
  String hexToBt4(String hex) {
    int index = "0123456789ABCDEF".indexOf(hex);
    if (index == -1) return "";
    return [(index>>3) % 2, (index>>2) % 2,(index>>1) % 2,index % 2].join();
  }

  String bt64ToHex(List<int> byteData) {
    String hex = "";
    for (int i = 0; i < 16; i++) {
      List<int> bt = List.generate(4, (index) => byteData[i * 4 + index]);
      hex += bt4ToHex(bt.join());
    }
    return hex;
  }

  /*
		 * the 64 bit des core arithmetic
		 */
  List<int> enc(List<int> dataByte, List<int> keyByte) {
    List<List<int>> keys = generateKeys(keyByte);
    List<int> ipByte = initPermute(dataByte);
    List<int> ipLeft = List.generate(32, (index) => ipByte[index]);
    List<int> ipRight = List.generate(32, (index) => ipByte[32 + index]);

    for (int i = 0; i < 16; i++) {
      var tempLeft = ipLeft;
      ipLeft = ipRight;

      List<int> key = List.generate(48, (index) => keys[i][index]);
      ipRight = xor(pPermute(sBoxPermute(xor(expandPermute(ipRight), key))), tempLeft);
    }

    List<int> finalData = List.generate(64, (i) => i < 32 ? ipRight[i] : ipLeft[i-32]);
    return finallyPermute(finalData);
  }

  List<int> initPermute(List<int> originalData) {
    List<int> ipByte = List.filled(64, 0);
    for (int i = 0, m = 1, n = 0; i < 4; i++, m += 2, n += 2) {
      for (int j = 7, k = 0; j >= 0; j--, k++) {
        ipByte[i * 8 + k] = originalData[j * 8 + m];
        ipByte[i * 8 + k + 32] = originalData[j * 8 + n];
      }
    }
    return ipByte;
  }

  List<int> expandPermute(List<int> rightData) {
    List<int> epByte = List.filled(48, 0);
    for (int i = 0; i < 8; i++) {
      if (i == 0) {
        epByte[i * 6 + 0] = rightData[31];
      } else {
        epByte[i * 6 + 0] = rightData[i * 4 - 1];
      }
      epByte[i * 6 + 1] = rightData[i * 4 + 0];
      epByte[i * 6 + 2] = rightData[i * 4 + 1];
      epByte[i * 6 + 3] = rightData[i * 4 + 2];
      epByte[i * 6 + 4] = rightData[i * 4 + 3];
      if (i == 7) {
        epByte[i * 6 + 5] = rightData[0];
      } else {
        epByte[i * 6 + 5] = rightData[i * 4 + 4];
      }
    }
    return epByte;
  }

  List<int> xor(List<int> byteOne, List<int> byteTwo) {
    return List.generate(byteOne.length, (i) => byteOne[i] ^ byteTwo[i]);
  }

  List<int> sBoxPermute(List<int> expandByte) {
    List<int> sBoxByte = List.filled(32, 0);
    String binary = "";
    const List<List<int>> s1 = [[ 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 ], [ 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 ],
      [ 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 ], [ 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 ] ];

    /* Table - s2 */
    const List<List<int>> s2 = [ [ 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 ], [ 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 ],
      [ 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 ], [ 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 ] ];

    /* Table - s3 */
    const List<List<int>> s3 = [ [ 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 ], [ 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 ],
      [ 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 ], [ 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 ] ];
    /* Table - s4 */
    const List<List<int>> s4 = [ [ 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 ], [ 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 ],
      [ 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 ], [ 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 ] ];

    /* Table - s5 */
    const List<List<int>> s5 = [ [ 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 ], [ 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 ],
      [ 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 ], [ 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 ] ];

    /* Table - s6 */
    const List<List<int>> s6 = [ [ 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 ], [ 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 ],
      [ 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 ], [ 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 ] ];

    /* Table - s7 */
    const List<List<int>> s7 = [ [ 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 ], [ 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 ],
      [ 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 ], [ 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 ] ];

    /* Table - s8 */
    const List<List<int>> s8 = [ [ 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 ], [ 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 ],
      [ 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 ], [ 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 ] ];

    const List<List<List<int>>> ss = [s1,s2,s3,s4,s5,s6,s7,s8];

    for (int m = 0; m < 8; m++) {
      int i = 0, j = 0;
      i = expandByte[m * 6 + 0] * 2 + expandByte[m * 6 + 5];
      j = expandByte[m * 6 + 1] * 2 * 2 * 2 + expandByte[m * 6 + 2] * 2 * 2 + expandByte[m * 6 + 3] * 2 + expandByte[m * 6 + 4];
      binary = getBoxBinary(ss[m][i][j]);
      sBoxByte[m * 4 + 0] = int.parse(binary.substring(0, 1));
      sBoxByte[m * 4 + 1] = int.parse(binary.substring(1, 2));
      sBoxByte[m * 4 + 2] = int.parse(binary.substring(2, 3));
      sBoxByte[m * 4 + 3] = int.parse(binary.substring(3, 4));
    }
    return sBoxByte;
  }


  List<int> pPermute(List<int> sBoxByte) {
    const List<int> tbl = [15,6,19,20,28,11,27,16,0,14,22,25,4,17,30,9,1,7,23,13,31,26,2,8,18,12,29,5,21,10,3,24];
    return List.generate(32, (index) => sBoxByte[tbl[index]]);
  }

  List<int> finallyPermute(List<int> endByte) {
    const List<int> tbl = [39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25,32,0,40,8,48,16,56,24];
    return List.generate(64, (index) => endByte[tbl[index]]);
  }

  String getBoxBinary(int i) {
    const List<String> tbls = [
      "0000", "0001", "0010", "0011",
      "0100", "0101", "0110", "0111",
      "1000", "1001", "1010", "1011",
      "1100", "1101", "1110", "1111"
    ];
    if (i >= 0 && i < tbls.length) return tbls[i];
    return "";
  }

  /*
		 * generate 16 keys for xor
		 */
  List<List<int>> generateKeys(List<int> keyByte) {
    List<int> key = List.filled(56, 0);
    List<List<int>> keys = List.generate(16, (_) => List.filled(48, 0));

    List<int> loop = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 ];

    for (int i = 0; i < 7; i++) {
      for (int j = 0, k = 7; j < 8; j++, k--) {
        key[i * 8 + j] = keyByte[8 * k + i];
      }
    }

    const List<int> keyTbl = [13,16,10,23,0,4,2,27,14,5,20,9,22,18,11,3,25,7,15,6,26,19,12,1,40,51,30,36,46,54,29,39,50,44,32,47,43,48,38,55,33,52,45,41,49,35,28,31];
    int i = 0;
    for (i = 0; i < 16; i++) {
      int tempLeft = 0;
      int tempRight = 0;
      for (int j = 0; j < loop[i]; j++) {
        tempLeft = key[0];
        tempRight = key[28];
        for (int k = 0; k < 27; k++) {
          key[k] = key[k + 1];
          key[28 + k] = key[29 + k];
        }
        key[27] = tempLeft;
        key[55] = tempRight;
      }

      List<int> tempKey = List.generate(48, (index) => key[keyTbl[index]]);
      keys[i].setRange(0, 48, tempKey);
    }
    return keys;
  }
}
