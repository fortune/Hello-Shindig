/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.apache.shindig.social.core.oauth;

import com.google.inject.Inject;

import net.oauth.OAuth;
import net.oauth.OAuthAccessor;
import net.oauth.OAuthConsumer;
import net.oauth.OAuthException;
import net.oauth.OAuthMessage;
import net.oauth.OAuthValidator;
import net.oauth.SimpleOAuthValidator;
import net.oauth.OAuthProblemException;
import net.oauth.server.OAuthServlet;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.shindig.auth.AuthenticationHandler;
import org.apache.shindig.auth.OAuthConstants;
import org.apache.shindig.auth.SecurityToken;
import org.apache.shindig.common.util.CharsetUtil;
import org.apache.shindig.social.opensocial.oauth.OAuthDataStore;
import org.apache.shindig.social.opensocial.oauth.OAuthEntry;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URISyntaxException;
import java.util.Arrays;

import javax.servlet.http.HttpServletRequest;

/**
 * Handle both 2-legged consumer and full 3-legged OAuth requests.
 */
public class OAuthAuthenticationHandler implements AuthenticationHandler {

  public static final String REQUESTOR_ID_PARAM = "xoauth_requestor_id";

  private final OAuthDataStore store;

  @Inject
  public OAuthAuthenticationHandler(OAuthDataStore store) {
    this.store = store;
  }

  public String getName() {
    return "OAuth";
  }

  public String getWWWAuthenticateHeader(String realm) {
    return String.format("OAuth realm=\"%s\"", realm);
  }

  public SecurityToken getSecurityTokenFromRequest(HttpServletRequest request)
    throws InvalidAuthenticationException {

    //
    // HttpServletRequest から作成した OAuthMessage には、OAuth 関連の解析がし易いように
    // 含まれるすべてのヘッダのコピーやパラメータのコピーが入っている。
    //
    OAuthMessage message = OAuthServlet.getMessage(request, null);
    
    //
    // OAuth シグネチャが含まれていないなら、OAuth リクエストではない。
    //
    if (StringUtils.isEmpty(getParameter(message, OAuth.OAUTH_SIGNATURE))) {
      // Is not an oauth request
      return null;
    }
    
    //
    // body hash 拡張仕様をサポート
    //
    String bodyHash = getParameter(message, OAuthConstants.OAUTH_BODY_HASH);
    if (!StringUtils.isEmpty(bodyHash)) {
      verifyBodyHash(request, bodyHash);
    }
    try {
      //
      // OAuth を認証し、成功すれば、セキュリティトークンを作成して返す。
      //
      return verifyMessage(message);
    } catch (OAuthProblemException oauthException) {
      throw new InvalidAuthenticationException("OAuth Authentication Failure", oauthException);
    }
  }

  //
  // OAuth 情報が格納された message から、署名のチェック等を行い、
  // 妥当であれば、セキュリティトークンを作成して返す。
  //
  // message 中に oauth_token が含まれているなら 3-legged であり、
  // そうでないなら 2-legged である。
  //
  // 3-legged にしろ、2-legged にしろ、このトークンを元にコンテナがもつ情報へアクセスする。
  //
  protected SecurityToken verifyMessage(OAuthMessage message)
    throws OAuthProblemException {
    OAuthEntry entry = getOAuthEntry(message);
    OAuthConsumer authConsumer = getConsumer(message);

    OAuthAccessor accessor = new OAuthAccessor(authConsumer);

    //
    // 3-legged oauth の場合。
    // このとき、アクセストークンとトークンシークレットがあるはず。
    //
    if (entry != null) {
      accessor.tokenSecret = entry.getTokenSecret();
      accessor.accessToken = entry.getToken();
    }

    try {
      //
      // 署名を検証する。
      //
      OAuthValidator validator = new SimpleOAuthValidator();
      validator.validateMessage(message, accessor);
    } catch (OAuthProblemException e) {
      throw e;
    } catch (OAuthException e) {
      OAuthProblemException ope = new OAuthProblemException(OAuth.Problems.SIGNATURE_INVALID);
      ope.setParameter(OAuth.Problems.OAUTH_PROBLEM_ADVICE, e.getMessage());
      throw ope;
    } catch (IOException e) {
      OAuthProblemException ope = new OAuthProblemException(OAuth.Problems.SIGNATURE_INVALID);
      ope.setParameter(OAuth.Problems.OAUTH_PROBLEM_ADVICE, e.getMessage());
      throw ope;
    } catch (URISyntaxException e) {
      OAuthProblemException ope = new OAuthProblemException(OAuth.Problems.SIGNATURE_INVALID);
      ope.setParameter(OAuth.Problems.OAUTH_PROBLEM_ADVICE, e.getMessage());
      throw ope;
    }
    return getTokenFromVerifiedRequest(message, entry, authConsumer);  // セキュリティトークンを作成
  }

  //
  // message 中の oauth_token に紐付く認証情報をデータソースから引き出す。
  // oauth_token がない場合は、2-legged oauth によるリクエストだったということであり、その場合、null を返す。
  //
  // oauth_token に紐付く認証情報がない場合は、そもそもそのトークンが不正ということであり、例外をスローする。
  // また、トークンのタイプがアクセストークンでない場合や、期限切れだった場合も例外になる。
  //
  protected OAuthEntry getOAuthEntry(OAuthMessage message) throws OAuthProblemException {
    OAuthEntry entry = null;
    String token = getParameter(message, OAuth.OAUTH_TOKEN);
    if (!StringUtils.isEmpty(token))  {
      entry = store.getEntry(token);
      if (entry == null) {
        OAuthProblemException e = new OAuthProblemException(OAuth.Problems.TOKEN_REJECTED);
        e.setParameter(OAuth.Problems.OAUTH_PROBLEM_ADVICE, "cannot find token");
        throw e;
      } else if (entry.getType() != OAuthEntry.Type.ACCESS) {
        OAuthProblemException e = new OAuthProblemException(OAuth.Problems.TOKEN_REJECTED);
        e.setParameter(OAuth.Problems.OAUTH_PROBLEM_ADVICE, "token is not an access token");
        throw e;
      } else if (entry.isExpired()) {
        throw new OAuthProblemException(OAuth.Problems.TOKEN_EXPIRED);
      }
    }
    return entry;
  }

  //
  // message 中に含まれるはずの oauth_consumer_key から Consumer 情報を引き出す。
  // 3-legged でも 2-legged でも consumer key は必須である。したがって、必ず Consumer 情報を取得できるはずであり、
  // 取得できない場合は例外になる。ただし、2-legged の場合、oauth_consumer_key には、アプリケーションの ID が入っているので
  // アプリケーションの情報になるだろう。
  //
  protected OAuthConsumer getConsumer(OAuthMessage message) throws OAuthProblemException {
    String consumerKey = getParameter(message, OAuth.OAUTH_CONSUMER_KEY);
    OAuthConsumer authConsumer = store.getConsumer(consumerKey);
    if (authConsumer == null) {
      throw new OAuthProblemException(OAuth.Problems.CONSUMER_KEY_UNKNOWN);
    }
    return authConsumer;
  }

  //
  // セキュリティトークンを作成する。
  //
  // entry が null なら 2-legged oauth と見なす。
  //
  protected SecurityToken getTokenFromVerifiedRequest(OAuthMessage message, OAuthEntry entry,
                                                      OAuthConsumer authConsumer) throws OAuthProblemException {
    if (entry != null) {
      return new OAuthSecurityToken(entry.getUserId(), entry.getCallbackUrl(), entry.getAppId(),
                                    entry.getDomain(), entry.getContainer(), entry.expiresAt().getTime());
    } else {
      //
      // アプリケーションの ID（consumerKey で指定されている）と ownerId （userId で指定）から
      // 2-legged 用のセキュリティトークンを作成。ownerId がアプリケーションをインストールしているかどうかもチェックされる。
      //
      String userId = getParameter(message, REQUESTOR_ID_PARAM);
      return store.getSecurityTokenForConsumerRequest(authConsumer.consumerKey, userId);
    }
  }

  public static byte[] readBody(HttpServletRequest request) throws IOException {
    if (request.getAttribute(AuthenticationHandler.STASHED_BODY) != null) {
      return (byte[])request.getAttribute(AuthenticationHandler.STASHED_BODY);
    }
    byte[] rawBody = IOUtils.toByteArray(request.getInputStream());
    request.setAttribute(AuthenticationHandler.STASHED_BODY, rawBody);
    return rawBody;
  }

  public static String readBodyString(HttpServletRequest request) throws IOException {
    byte[] rawBody = readBody(request);
    return IOUtils.toString(new ByteArrayInputStream(rawBody), request.getCharacterEncoding());
  }

  //
  // OAuth Body Hash をサポートしている。
  //
  // OAuth の元々の仕様では、リクエストボディの内容が署名のベース文字列に含まれるのは、リクエストボディの
  // Content-Type が application/x-www-form-urlencoded のときのみだった。body hash 拡張仕様で、
  // それ以外の場合も署名のベース文字列として使えるようになる。これにより、ボディ内容を改竄される危険が減る。
  //
  public static void verifyBodyHash(HttpServletRequest request, String oauthBodyHash)
    throws InvalidAuthenticationException {
    // we are doing body hash signing which is not permitted for form-encoded data
    if (request.getContentType() != null && request.getContentType().contains(OAuth.FORM_ENCODED)) {
      throw new AuthenticationHandler.InvalidAuthenticationException(
        "Cannot use oauth_body_hash with a Content-Type of application/x-www-form-urlencoded",
        null);
    } else {
      try {
        byte[] rawBody = readBody(request);
        byte[] received = Base64.decodeBase64(CharsetUtil.getUtf8Bytes(oauthBodyHash));
        byte[] expected = DigestUtils.sha(rawBody);
        if (!Arrays.equals(received, expected)) {
          throw new AuthenticationHandler.InvalidAuthenticationException(
            "oauth_body_hash failed verification", null);
        }
      } catch (IOException ioe) {
        throw new AuthenticationHandler.InvalidAuthenticationException(
          "Unable to read content body for oauth_body_hash verification", null);
      }
    }
  }

  public static String getParameter(OAuthMessage requestMessage, String key) {
    try {
      return StringUtils.trim(requestMessage.getParameter(key));
    } catch (IOException e) {
      return null;
    }
  }
}
