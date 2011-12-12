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
package org.apache.shindig.sample.container;

import org.apache.shindig.gadgets.http.HttpFetcher;
import org.apache.shindig.gadgets.oauth.OAuthFetcherConfig;
import org.apache.shindig.gadgets.render.Renderer;
import org.apache.shindig.sample.ext.ExtRenderer;
import org.apache.shindig.sample.ext.NoFetchOAuthRequest;

import com.google.inject.AbstractModule;
import com.google.inject.Inject;
import com.google.inject.Provider;
import com.google.inject.multibindings.Multibinder;
import com.google.inject.name.Names;

public class SampleContainerGuiceModule extends AbstractModule {

	protected void configure() {
		// We do this so that jsecurity realms can get access to the
		// jsondbservice singleton

		Multibinder<Object> handlerBinder = Multibinder.newSetBinder(binder(),
				Object.class, Names.named("org.apache.shindig.handlers"));
		handlerBinder.addBinding().toInstance(SampleContainerHandler.class);

		// NG ワード検出 API をバインド
		handlerBinder.addBinding().toInstance(NgWordHandler.class);
		
		//
		// Gadget レンダリング用の Renderer クラスオブジェクトを Inject するところでは
		// ExtRenderer を bind するように設定する。Renderer はインターフェースでなくクラスなので、
		// Shindig 内部では、明示的に bind していないだろう。もし bind していたら、
		// ここでの設定と衝突してしまうだろう。
		// TODO
		//
		bind(Renderer.class).to(ExtRenderer.class);
		
		bind(NoFetchOAuthRequest.class).toProvider(NoFetchOAuthRequestProvider.class);
	}

	
	//
	// org.apache.shindig.gadgets.oauth.OAuthModule 内で
	// OAuthRequest の Provider を定義しているので、それに習って Fetch 操作をサポートしない OAuthRequest の
	// Provider を定義した。
	//
	public static class NoFetchOAuthRequestProvider implements Provider<NoFetchOAuthRequest> {
		private final HttpFetcher fetcher;
		private final OAuthFetcherConfig config;

		@Inject
		public NoFetchOAuthRequestProvider(HttpFetcher fetcher, OAuthFetcherConfig config) {
			this.fetcher = fetcher;
			this.config = config;
		}

		public NoFetchOAuthRequest get() {
			return new NoFetchOAuthRequest(config, fetcher);
		}
	}
}