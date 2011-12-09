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
package org.apache.shindig.protocol;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.shindig.auth.SecurityToken;
import org.apache.shindig.common.servlet.HttpUtil;
import org.apache.shindig.common.util.JsonConversionUtil;
import org.apache.shindig.protocol.multipart.FormDataItem;
import org.apache.shindig.protocol.multipart.MultipartFormParser;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.inject.Inject;
import com.google.inject.name.Named;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.Writer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Future;

/**
 * JSON-RPC handler servlet.
 */
public class JsonRpcServlet extends ApiServlet {

  //
  // JSON RPC リクエストが HTTP POST だった場合、リクエストボディは JSON 形式で表現されたリクエスト内容になるので、
  // Content-type は、JSON を指定するものでなければならない。
  //
  // POST リクエストの Content-type は multipart/form-data でもよい。この場合、マルチパートなリクエストボディ中で、
  // 予約済みのフィールド名 "request" に対応するボディの Content-type が JSON 形式であり、それがリクエスト内容になる。
  // その他のフィールド名とそのコンテンツは、"request" フィールドで指定された JSON リクエストのパラメータとその値として使われる。
  // これにより、イメージ等のアップロードを JSON RPC で処理することができるようになる。
  //
  public static final Set<String> ALLOWED_CONTENT_TYPES =
      new ImmutableSet.Builder<String>().addAll(ContentTypes.ALLOWED_JSON_CONTENT_TYPES)
          .addAll(ContentTypes.ALLOWED_MULTIPART_CONTENT_TYPES).build();

  /**
   * In a multipart request, the form item with field name "request" will contain the
   * actual request, per the proposed Opensocial 0.9 specification.
   */
  public static final String REQUEST_PARAM = "request";
  
  private MultipartFormParser formParser;

  @Inject
  void setMultipartFormParser(MultipartFormParser formParser) {
    this.formParser = formParser;
  }
  
  //
  // JSON RPC のレスポンスにおいて、結果のデータは "result" というフィールド名で返すというのが仕様のようだ。
  // それをカスタマイズできるようだが、そのような必要性はあるのだろうか？
  //
  private String jsonRpcResultField = "result";
  private boolean jsonRpcBothFields = false;
  @Inject
  void setJsonRpcResultField(@Named("shindig.json-rpc.result-field")String jsonRpcResultField) {
    this.jsonRpcResultField = jsonRpcResultField;
    jsonRpcBothFields = "both".equals(jsonRpcResultField);
  }

  @Override
  protected void service(HttpServletRequest servletRequest, HttpServletResponse servletResponse)
      throws IOException {
    //
    // JSON RPC なので、レスポンスの Content-type は当然、JSON である。
    //
    setCharacterEncodings(servletRequest, servletResponse);
    servletResponse.setContentType(ContentTypes.OUTPUT_JSON_CONTENT_TYPE);

    // only GET/POST
    String method = servletRequest.getMethod();

    if (!("GET".equals(method) || "POST".equals(method))) {
      sendError(servletResponse, 
                new ResponseItem(HttpServletResponse.SC_BAD_REQUEST, "Only POST/GET Allowed"));
      return;
    }

    //
    // セキュリティトークンは必須。
    // このサーブレットの前に置かれている Filter 内でリクエストから生成されている。
    //
    SecurityToken token = getSecurityToken(servletRequest);
    if (token == null) {
      sendSecurityError(servletResponse);
      return;
    }

    //
    // CORS 設定
    //
    HttpUtil.setCORSheader(servletResponse, containerConfig.<String>getList(token.getContainer(), "gadgets.parentOrigins"));

    try {
      String content = null;
      String callback = null; // for JSONP
      Map<String,FormDataItem> formData = Maps.newHashMap();

      // Get content or deal with JSON-RPC GET
      //
      // POST の場合
      // JSONP の GET の場合
      // JSONP 以外の GET の場合
      //
      // で処理を分ける。
      //
      // POST の場合、リクエストボディから JSON 形式のリクエスト内容を取り出す。HTTP リクエストが multipart/form-data だったときは、
      // FormDataItem とそれのフィールド名のマップを取り出す。
      //
      if ("POST".equals(method)) {
        content = getPostContent(servletRequest, formData);
      } else if (HttpUtil.isJSONP(servletRequest)) {
        content = servletRequest.getParameter("request");
        callback = servletRequest.getParameter("callback");
      } else {
        // GET request, fromRequest() creates the json objects directly.
        JSONObject request = JsonConversionUtil.fromRequest(servletRequest);

        if (request != null) {
          dispatch(request, formData, servletRequest, servletResponse, token, null);
          return;
        }
      }
      
      if (content == null) {
        sendError(servletResponse, new ResponseItem(HttpServletResponse.SC_BAD_REQUEST, "No content specified"));
        return;
      }

      //
      // JSON 形式である content が JSON バッチリクエストであるかどうかに応じて分岐。
      //
      if (isContentJsonBatch(content)) {
        JSONArray batch = new JSONArray(content);
        dispatchBatch(batch, formData, servletRequest, servletResponse, token, callback);
      } else {
        JSONObject request = new JSONObject(content);
        dispatch(request, formData, servletRequest, servletResponse, token, callback);
      }
      return;
    } catch (JSONException je) {
      sendJsonParseError(je, servletResponse);
    } catch (IllegalArgumentException e) {
      // a bad jsonp request..
      sendBadRequest(e, servletResponse);
    }  catch (ContentTypes.InvalidContentTypeException icte) {
      sendBadRequest(icte, servletResponse);
    }
  }

  
  
  //
  // POST リクエストボディからリクエストを読み取る。
  //
  // request から JSON リクエスト内容を読み取って、返す。また、multipart/form-data だった場合、
  // リクエスト内容以外のフィールド名とそのコンテンツを formItems にセットする。
  // 
  protected String getPostContent(HttpServletRequest request, Map<String,FormDataItem> formItems)
      throws ContentTypes.InvalidContentTypeException, IOException {
    String content = null;

    ContentTypes.checkContentTypes(ALLOWED_CONTENT_TYPES, request.getContentType());

    if (formParser.isMultipartContent(request)) {
      for (FormDataItem item : formParser.parse(request)) {
        if (item.isFormField() && REQUEST_PARAM.equals(item.getFieldName()) && content == null) {
          // As per spec, in case of a multipart/form-data content, there will be one form field
          // with field name as "request". It will contain the json request. Any further form
          // field or file item will not be parsed out, but will be exposed via getFormItem
          // method of RequestItem.
          if (!StringUtils.isEmpty(item.getContentType())) {
            ContentTypes.checkContentTypes(ContentTypes.ALLOWED_JSON_CONTENT_TYPES, item.getContentType());
          }
          content = item.getAsString();
        } else {
          formItems.put(item.getFieldName(), item);
        }
      }
    } else {
      //
      // multipart/form-data でないなら、リクエストボディがそのまま JSON リクエスト内容になる。
      //
      content = IOUtils.toString(request.getInputStream(), request.getCharacterEncoding());
    }
    return content;
  }
  


  //
  // JSON RPC バッチリクエストを処理する。
  //
  // batch 中には、JSON RPC リクエスト内容を表現する JSON の配列が格納されている。それを順々に処理し、
  // 結果を HttpServletResponse に出力する。
  //
  protected void dispatchBatch(JSONArray batch, Map<String, FormDataItem> formItems ,
      HttpServletRequest servletRequest, HttpServletResponse servletResponse,
      SecurityToken token, String callback) throws JSONException, IOException {
    // Use linked hash map to preserve order
    List<Future<?>> responses = Lists.newArrayListWithCapacity(batch.length());

    // Gather all Futures.  We do this up front so that
    // the first call to get() comes after all futures are created,
    // which allows for implementations that batch multiple Futures
    // into single requests.
    for (int i = 0; i < batch.length(); i++) {
      JSONObject batchObj = batch.getJSONObject(i);
      responses.add(getHandler(batchObj, servletRequest).execute(formItems, token, jsonConverter));
    }

    // Resolve each Future into a response.
    // TODO: should use shared deadline across each request
    List<Object> result = new ArrayList<Object>(batch.length());
    for (int i = 0; i < batch.length(); i++) {
      JSONObject batchObj = batch.getJSONObject(i);
      String key = null;
      if (batchObj.has("id")) {
        key = batchObj.getString("id");
      }
      result.add(getJSONResponse(key, getResponseItem(responses.get(i))));
    }

    // Generate the output
    Writer writer = servletResponse.getWriter();
    if (callback != null) writer.append(callback).append('(');
    jsonConverter.append(writer, result);
    if (callback != null) writer.append(");\n");
  }

  protected void dispatch(JSONObject request, Map<String, FormDataItem> formItems,
      HttpServletRequest servletRequest, HttpServletResponse servletResponse,
      SecurityToken token, String callback) throws JSONException, IOException {
    String key = null;

    if (request.has("id")) {
      key = request.getString("id");
    }

    // getRpcHandler never returns null
    Future<?> future = getHandler(request, servletRequest).execute(formItems, token, jsonConverter);

    // Resolve each Future into a response.
    // TODO: should use shared deadline across each request
    ResponseItem response = getResponseItem(future);
    Object result = getJSONResponse(key, response);

    // Generate the output
    Writer writer = servletResponse.getWriter();
    if (callback != null) writer.append(callback).append('(');
    jsonConverter.append(writer, result);
    if (callback != null) writer.append(");\n");
  }

  /**
   * 
   */
  protected void addResult(Map<String,Object> result, Object data) {
    if (jsonRpcBothFields) {
      result.put("result", data);
      result.put("data", data);
    }
    result.put(jsonRpcResultField, data);
  }

  /**
   * Determine if the content contains a batch request
   * 
   * JSON RPC のリクエスト内容は、{ "method": "echo", "params":[Hello JSON-RPC"], "id":1 } のように指定するが、
   * これを [] の中に並べることで複数のメソッドを実行できる。これがバッチリクエストだ。
   *
   * @param content json content or null
   * @return true if content contains is a json array, not a json object or null
   */
  private boolean isContentJsonBatch(String content) {
    if (content == null) return false;
    return ((content.indexOf('[') != -1) && content.indexOf('[') < content.indexOf('{'));
  }
  
  
  
  /**
   * Wrap call to dispatcher to allow for implementation specific overrides
   * and servlet-request contextual handling
   */
  protected RpcHandler getHandler(JSONObject rpc, HttpServletRequest request) {
    return dispatcher.getRpcHandler(rpc);
  }

  Object getJSONResponse(String key, ResponseItem responseItem) {
    Map<String, Object> result = Maps.newHashMap();
    if (key != null) {
      result.put("id", key);
    }
    if (responseItem.getErrorCode() < 200 ||
        responseItem.getErrorCode() >= 400) {
      result.put("error", getErrorJson(responseItem));
    } else {
      Object response = responseItem.getResponse();
      if (response instanceof DataCollection) {
        addResult(result, ((DataCollection) response).getEntry());
      } else if (response instanceof RestfulCollection) {
        Map<String, Object> map = Maps.newHashMap();
        RestfulCollection<?> collection = (RestfulCollection<?>) response;
        // Return sublist info
        if (collection.getTotalResults() != collection.getEntry().size()) {
          map.put("startIndex", collection.getStartIndex());
          map.put("itemsPerPage", collection.getItemsPerPage());
        }
        // always put in totalResults
        map.put("totalResults", collection.getTotalResults());

        if (!collection.isFiltered())
          map.put("filtered", collection.isFiltered());

        if (!collection.isUpdatedSince())
          map.put("updatedSince", collection.isUpdatedSince());

        if (!collection.isSorted())
          map.put("sorted", collection.isUpdatedSince());

        map.put("list", collection.getEntry());
        addResult(result, map);
      } else {
        addResult(result, response);
      }

      // TODO: put "code" for != 200?
    }
    return result;
  }

  /** Map of old-style error titles */
  private static final Map<Integer, String> errorTitles = ImmutableMap.<Integer, String> builder()
     .put(HttpServletResponse.SC_NOT_IMPLEMENTED, "notImplemented")
     .put(HttpServletResponse.SC_UNAUTHORIZED, "unauthorized")
     .put(HttpServletResponse.SC_FORBIDDEN, "forbidden")
     .put(HttpServletResponse.SC_BAD_REQUEST, "badRequest")
     .put(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "internalError")
     .put(HttpServletResponse.SC_EXPECTATION_FAILED, "limitExceeded")
     .build();
        
  // TODO(doll): Refactor the responseItem so that the fields on it line up with this format.
  // Then we can use the general converter to output the response to the client and we won't
  // be harcoded to json.
  private Object getErrorJson(ResponseItem responseItem) {
    Map<String, Object> error = new HashMap<String, Object>(2, 1);
    error.put("code", responseItem.getErrorCode());

    String message = errorTitles.get(responseItem.getErrorCode());
    if (message == null) {
      message = responseItem.getErrorMessage();
    } else {
      if (StringUtils.isNotBlank(responseItem.getErrorMessage())) {
        message += ": " + responseItem.getErrorMessage();
      }
    }
    
    if (StringUtils.isNotBlank(message)) {
      error.put("message", message);
    }

    if (responseItem.getResponse() != null) {
      error.put("data", responseItem.getResponse());
    }

    return error;
  }

  @Override
  protected void sendError(HttpServletResponse servletResponse, ResponseItem responseItem)
      throws IOException {
    jsonConverter.append(servletResponse.getWriter(), getErrorJson(responseItem));

    servletResponse.setStatus(responseItem.getErrorCode());
  }

  private void sendBadRequest(Throwable t, HttpServletResponse response) throws IOException {
    sendError(response, new ResponseItem(HttpServletResponse.SC_BAD_REQUEST,
        "Invalid input - " + t.getMessage()));
  }

  private void sendJsonParseError(JSONException e, HttpServletResponse response) throws IOException {
    sendError(response, new ResponseItem(HttpServletResponse.SC_BAD_REQUEST,
        "Invalid JSON - " + e.getMessage()));
  }
}
