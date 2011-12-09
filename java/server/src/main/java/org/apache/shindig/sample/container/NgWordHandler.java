package org.apache.shindig.sample.container;

import java.util.concurrent.Future;

import javax.servlet.http.HttpServletResponse;

import net.java.sen.StringTagger;
import net.java.sen.Token;

import org.apache.shindig.common.util.ImmediateFuture;
import org.apache.shindig.protocol.Operation;
import org.apache.shindig.protocol.ProtocolException;
import org.apache.shindig.protocol.RequestItem;
import org.apache.shindig.protocol.RestfulCollection;
import org.apache.shindig.protocol.Service;

import com.google.common.collect.ImmutableList;



//
// POST メソッドで、リクエストボディを
//
//	{ body: "チェックしたい文字列をここに入れる" }
//
// のようにすると、形態素解析ライブラリ Sen を使って、文字列を解析し、
// NG ワードが含まれているかどうかチェックする。OK, つまり含まれていないなら
//
//	{
//		"entry": [ { "valid": true } ]
//	}
//
// が返される。ページングサポートなので、startIndex, totalResults, itemsPerPage という
// プロパティも含まれる。NG, つまり含まれているなら、valid が false になっている。
//
@Service(name = "ngword")
public class NgWordHandler {
	
	public static final String NG_WORD = "NGWORD";
	
	
	
	public static class Entry {
		private boolean valid;
		public Entry(boolean valid) {
			this.valid = valid;
		}
		public boolean getValid() { return valid; }
	}
	
	public static class Message {
		private String body;
		public void setBody(String body) { this.body = body; }
	}
	
	@Operation(httpMethods = "POST")
	public Future<?> check(RequestItem request) {
		String content = request.getParameter("body");
		if (content == null) {
			throw new ProtocolException(HttpServletResponse.SC_BAD_REQUEST, "");
		}
		String body = request.getTypedParameter("body", Message.class).body;
		if (body == null) {
			throw new ProtocolException(HttpServletResponse.SC_BAD_REQUEST, "");
		}
		
		// body の長さに制限を設けるべきだろう。TODO
		
		try {
			// StringTagger はスレッドセーフでないので、その都度作成しないといけないが、
			// 時間がかかるのは最初に作成するときのみ。実際に辞書を読み込んでいるのは最初の１回だけなのだろう。
			// したがって、もし辞書を変更したら、再起動しないといけない。
			//
			StringTagger tagger = StringTagger.getInstance();
			Token[] tokens = tagger.analyze(body);
			for (Token token: tokens) {
				if ( NG_WORD.equals(token.getBasicString()) ) {
					return ImmediateFuture.newInstance( new RestfulCollection<Entry>( ImmutableList.of( new Entry(false) ) ) );
				}
			}
			return ImmediateFuture.newInstance( new RestfulCollection<Entry>( ImmutableList.of( new Entry(true) ) ) );
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

}
