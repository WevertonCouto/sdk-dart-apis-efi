import 'dart:convert';
import 'dart:io';
import 'package:dio/dio.dart';

import 'config.dart';
import 'exception/authorization_exception.dart';
import 'package:flutter/services.dart' show rootBundle;

/// This class is responsible to create an HttpClient Object, generate the
/// request body and send it to a given endpoint. The send method return a
/// response for that request.

class Request {
  Dio _dio = Dio();
  Config _config = Config();

  Request() {
    if (this._config.conf.containsKey('certificate')) _addCerts();
  }

  Future<dynamic> send(
      String method, String route, dynamic requestOptions) async {
    var uri = this._config.conf['baseUri'] + route;

    var headers = {
      'Content-Type': 'application/json',
      'api-sdk': 'dart-${Config.version}',
    };

    if (requestOptions.containsKey('headers')) {
      headers.addAll(requestOptions['headers']);
    }

    if (this._config.conf.containsKey('headers')) {
      headers.addAll(this._config.conf['headers']);
    }

    if (this._config.conf['partnerToken'] != null &&
        this._config.conf['partnerToken'] != '') {
      headers['partner-token'] = this._config.conf['partnerToken'];
    }

    var bodyEncode = json.encode(requestOptions['body']);

    try {
      late Response response;
      if (method == 'GET') {
        response = await _dio.get(uri,
            queryParameters: requestOptions['queryParameters'],
            options: Options(headers: headers));
      } else if (method == 'POST') {
        response = await _dio.post(uri,
            data: bodyEncode, options: Options(headers: headers));
      } else if (method == 'PUT') {
        response = await _dio.put(uri,
            data: bodyEncode, options: Options(headers: headers));
      } else if (method == 'DELETE') {
        response = await _dio.delete(uri, options: Options(headers: headers));
      }

      if (response.statusCode == 401) {
        throw AuthorizationException(response.statusCode.toString());
      }

      var reply = response.data;

      if (reply != null) {
        var responseDecode = !reply.toString().contains('{')
            ? {"csv": reply}
            : json.decode(reply.toString());

        if (response.statusCode! > 299 || response.statusCode! < 200) {
          if (responseDecode.containsKey('error_description')) {
            throw Exception("Erro ao realizar requisição. \n code: " +
                response.statusCode.toString() +
                " \n message: " +
                responseDecode['error_description'].toString());
          } else {
            throw Exception("Erro ao realizar requisição. \n code: " +
                response.statusCode.toString() +
                " \n message: " +
                responseDecode['mensagem'].toString());
          }
        }
        return responseDecode;
      }
    } catch (e) {
      throw Exception("Erro ao realizar requisição: $e");
    }
  }

  void _addCerts() {
    // Carrega o certificado p12
    var certBytes = File('caminho_para_o_certificado.p12').readAsBytesSync();

    // Define a senha para o certificado, se necessário
    var password = 'senha_do_certificado';

    // Cria um contexto de segurança SSL com o certificado
    var context = SecurityContext.defaultContext;
    context.useCertificateChainBytes(certBytes, password: password);
    context.usePrivateKeyBytes(certBytes, password: password);

    // Configuração personalizada para o cliente Dio
    _dio = Dio(BaseOptions(
      baseUrl: _config.conf['baseUri'],
      headers: {
        'Content-Type': 'application/json',
        'api-sdk': 'dart-${Config.version}',
      },
      validateStatus: (status) {
        return status! >= 200 && status < 300;
      },
    ));
    _dio.httpClientAdapter = HttpClientAdapter();
  }
}


// class Request {
//   HttpClient _client = new HttpClient();
//   Config _config = new Config();

//   Request() {
//     if (this._config.conf.containsKey('certificate')) _addCerts();
//   }

//   Future<dynamic> send(
//       String method, String route, dynamic requestOptions) async {
//     HttpClientRequest request = await this
//         ._client
//         .openUrl(method, Uri.parse(this._config.conf['baseUri'] + route));

//     if (requestOptions.containsKey('headers'))
//       requestOptions['headers']
//           .keys
//           .forEach((k) => request.headers.add(k, requestOptions['headers'][k]));

//     if (this._config.conf.containsKey('headers'))
//       this._config.conf['headers'].keys.forEach(
//           (k) => request.headers.add(k, this._config.conf['headers'][k]));

//     request.headers.add('Content-Type', 'application/json');
//     request.headers.add('api-sdk', 'dart-${Config.version}');

//     if (this._config.conf['partnerToken'] != null &&
//         this._config.conf['partnerToken'] != '')
//       request.headers.add('partner-token', this._config.conf['partnerToken']);

//     String bodyEncode = json.encode(requestOptions['body']);

//     List<int> bodyutf = utf8.encode(bodyEncode);

//     request.contentLength = bodyutf.length;

//     request.add(bodyutf);

//     HttpClientResponse response = await request.close();

//     if (response.statusCode == 401)
//       return throw new AuthorizationException(response.statusCode.toString());

//     String reply = await response.transform(utf8.decoder).join();

//     if (reply != "") {
//       Map responseDecode =
//           !reply.contains('{') ? {"csv": reply} : json.decode(reply);

//       if (response.statusCode > 299 || response.statusCode < 200) {
//         if (responseDecode.containsKey('error_description'))
//           throw new Exception("Erro ao realizar requisição. \n code: " +
//               response.statusCode.toString() +
//               " \n message: " +
//               responseDecode['error_description'].toString());
//         else
//           throw new Exception("Erro ao realizar requisição. \n code: " +
//               response.statusCode.toString() +
//               " \n message: " +
//               responseDecode['mensagem'].toString());
//       }
//       return responseDecode;
//     }
//   }

//   void _addCerts() async {
//     SecurityContext context = SecurityContext.defaultContext;
//     final List<int> certificateChainBytes =
//         base64Decode(this._config.conf['certificate'].toString());
//     context.useCertificateChainBytes(certificateChainBytes);
//     context.usePrivateKeyBytes(certificateChainBytes);
//     this._client = new HttpClient(context: context);
//   }
// }
