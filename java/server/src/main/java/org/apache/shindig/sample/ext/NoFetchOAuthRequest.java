package org.apache.shindig.sample.ext;

import java.util.List;

import net.oauth.OAuth.Parameter;

import org.apache.shindig.gadgets.http.HttpFetcher;
import org.apache.shindig.gadgets.http.HttpRequest;
import org.apache.shindig.gadgets.http.HttpResponse;
import org.apache.shindig.gadgets.oauth.OAuthClientState;
import org.apache.shindig.gadgets.oauth.OAuthFetcherConfig;
import org.apache.shindig.gadgets.oauth.OAuthRequest;
import org.apache.shindig.gadgets.oauth.OAuthRequestException;
import org.apache.shindig.gadgets.oauth.OAuthResponseParams;


//
// OAuthRequest は、OAuth 認証のリクエストを実行するが、その際、OAuth 関連のパラメータは
// ヘッダではなくクエリーストリングに URL パラメータとして指定する。
//
// このクラスは、実際のリクエストは行わずに、どのようなリクエストになるのか調べたいときに使用する。
//
public class NoFetchOAuthRequest extends OAuthRequest {

	public NoFetchOAuthRequest(OAuthFetcherConfig fetcherConfig, HttpFetcher fetcher) {
		super(fetcherConfig, fetcher);
	}

	public NoFetchOAuthRequest(OAuthFetcherConfig fetcherConfig, HttpFetcher fetcher, List<Parameter> trustedParams) {
		super(fetcherConfig, fetcher, trustedParams);
	}

	//
	// このオブジェクトを使用して fetch メソッドを呼び出したときに実行されるリクエストを
	// 取得できる。
	//
	@Override
	public HttpRequest sanitizeAndSign(HttpRequest base, List<Parameter> params, boolean tokenEndpoint)
			throws OAuthRequestException {
		
		init(base);
		return super.sanitizeAndSign(base, params, tokenEndpoint);
	}

	//
	// fetch 操作はサポートしない。実行すると、UnsupportedOperationException がスローされる。
	//
	@Override
	public HttpResponse fetch(HttpRequest request) {
		throw new UnsupportedOperationException();
	}

	//
	// OAuthRequest オブジェクトの sanitizeAndSign メソッドを fetch メソッドをとおしてではなく
	// 直接呼び出すとエラーになってしまう。これは、fetch メソッドから始まる処理において初期化の一部が実行されて
	// いるためだ。そこで、その初期化処理をこのメソッドにコピーした。
	//
	// このメソッドを実行してから super.sanitizeAndSign メソッドを呼び出せばうまくいく。
	//
	private void init(HttpRequest request) {
		realRequest = request;
		clientState = new OAuthClientState(fetcherConfig.getStateCrypter(),
				request.getOAuthArguments().getOrigClientState());
		responseParams = new OAuthResponseParams(request.getSecurityToken(),
				request, fetcherConfig.getStateCrypter());
		try {
			accessorInfo = fetcherConfig.getTokenStore().getOAuthAccessor(
					realRequest.getSecurityToken(),
					realRequest.getOAuthArguments(), clientState,
					responseParams, fetcherConfig);
		} catch (OAuthRequestException e) {
			throw new RuntimeException(e);
		}
	}

}
