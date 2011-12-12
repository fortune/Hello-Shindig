/**
 * 
 */
package org.apache.shindig.sample.ext;

import java.util.List;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import javax.servlet.http.HttpServletResponse;
import org.apache.shindig.common.uri.Uri;
import org.apache.shindig.common.uri.UriBuilder;
import org.apache.shindig.config.ContainerConfig;
import org.apache.shindig.gadgets.Gadget;
import org.apache.shindig.gadgets.GadgetContext;
import org.apache.shindig.gadgets.GadgetException;
import org.apache.shindig.gadgets.LockedDomainService;
import org.apache.shindig.gadgets.http.HttpRequest;
import org.apache.shindig.gadgets.oauth.OAuthArguments;
import org.apache.shindig.gadgets.process.ProcessingException;
import org.apache.shindig.gadgets.process.Processor;
import org.apache.shindig.gadgets.render.HtmlRenderer;
import org.apache.shindig.gadgets.render.Renderer;
import org.apache.shindig.gadgets.render.RenderingException;
import org.apache.shindig.gadgets.render.RenderingResults;
import org.apache.shindig.gadgets.spec.View;

import com.google.common.base.Preconditions;
import com.google.inject.Inject;
import com.google.inject.Provider;

//
// type="url" の Gadget XML で authz="signed" が指定されていたとき
// リダイレクトURL に OAuth パラメータがつけられるようにしたクラス。
//
// これを Renderer の代わりに使用すれば、この機能がサポートされる。
//
// Renderer クラスは拡張されることを想定しておらず、private 変数・メソッドにアクセスできないので、
// そのままコピーして、必要な箇所を変更しなければならなかった。
//
public class ExtRenderer extends Renderer {
	private static final Logger LOG = Logger.getLogger(ExtRenderer.class.getName());
	private final Processor processor;
	private final HtmlRenderer renderer;
	private final ContainerConfig containerConfig;
	private final LockedDomainService lockedDomainService;

	private final Provider<NoFetchOAuthRequest> noFetchOAuthRequestProvider;

	@Inject
	public ExtRenderer(Processor processor, HtmlRenderer renderer,
			ContainerConfig containerConfig,
			LockedDomainService lockedDomainService,
			Provider<NoFetchOAuthRequest> provider) {

		super(processor, renderer, containerConfig, lockedDomainService);

		this.processor = processor;
		this.renderer = renderer;
		this.containerConfig = containerConfig;
		this.lockedDomainService = lockedDomainService;
		this.noFetchOAuthRequestProvider = provider;
	}

	/**
	 * Attempts to render the requested gadget.
	 * 
	 * @return The results of the rendering attempt.
	 * 
	 *         TODO: Localize error messages.
	 */
	@Override
	public RenderingResults render(GadgetContext context) {
		if (!validateParent(context)) {
			return RenderingResults.error(
					"Unsupported parent parameter. Check your container code.",
					HttpServletResponse.SC_BAD_REQUEST);
		}

		try {
			Gadget gadget = processor.process(context);

			if (gadget.getCurrentView() == null) {
				return RenderingResults.error(
						"Unable to locate an appropriate view in this gadget. "
								+ "Requested: '"
								+ gadget.getContext().getView()
								+ "' Available: "
								+ gadget.getSpec().getViews().keySet(),
						HttpServletResponse.SC_NOT_FOUND);
			}

			if (gadget.getCurrentView().getType() == View.ContentType.URL) {
				if (requiresCaja(gadget)) {
					return RenderingResults.error(
							"Caja does not support url type gadgets.",
							HttpServletResponse.SC_BAD_REQUEST);
				}

				switch (gadget.getCurrentView().getAuthType()) {
				case SIGNED:
				// case OAUTH:
					return RenderingResults.mustRedirect(getSignedUrl(gadget));
				default:
					return RenderingResults.mustRedirect(gadget.getCurrentView().getHref());
				}
			}

			if (!lockedDomainService.gadgetCanRender(context.getHost(), gadget,
					context.getContainer())) {
				return RenderingResults.error("Invalid domain",
						HttpServletResponse.SC_BAD_REQUEST);
			}

			return RenderingResults.ok(renderer.render(gadget));
		} catch (RenderingException e) {
			return logError(context.getUrl(), e.getHttpStatusCode(), e);
		} catch (ProcessingException e) {
			return logError(context.getUrl(), e.getHttpStatusCode(), e);
		} catch (RuntimeException e) {
			if (e.getCause() instanceof GadgetException) {
				return logError(context.getUrl(), ((GadgetException) e
						.getCause()).getHttpStatusCode(), e.getCause());
			}
			throw e;
		}
	}

	private Uri getSignedUrl(Gadget gadget) {
		View view = gadget.getCurrentView();
		Uri href = view.getHref();
		Preconditions.checkArgument(href != null,
				"Gadget does not have href for the current view");

		GadgetContext context = gadget.getContext();

		UriBuilder uri = new UriBuilder(href);

		try {
			//
			// 要るかな？
			// TODO
			//
			OAuthArguments oauthArgs = new OAuthArguments(view);
			oauthArgs.setProxiedContentRequest(true);

			HttpRequest request = new HttpRequest(uri.toUri()).setIgnoreCache(
					context.getIgnoreCache()).setOAuthArguments(oauthArgs)
					.setAuthType(view.getAuthType()).setSecurityToken(
							context.getToken()).setContainer(
							context.getContainer()).setGadget(
							gadget.getSpec().getUrl());

			//
			// この sanitizeAndSign メソッドの引数指定は、
			// OAuthRequest クラス内でリクエストを実行するときの同メソッドの使い方を参考にしている。
			//
			return noFetchOAuthRequestProvider.get().sanitizeAndSign(request, null, false).getUri();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	private RenderingResults logError(Uri gadgetUrl, int statusCode, Throwable t) {
		LOG.info("Failed to render gadget " + gadgetUrl + ": "
						+ t.getMessage());
		return RenderingResults.error(t.getMessage(), statusCode);
	}

	/**
	 * Returns true iff the gadget opts into the caja or the container forces
	 * caja by flag
	 */
	private boolean requiresCaja(Gadget gadget) {
		return gadget.getSpec().getModulePrefs().getFeatures().containsKey(
				"caja")
				|| "1".equals(gadget.getContext().getParameter("caja"));
	}

	/**
	 * Validates that the parent parameter was acceptable.
	 * 
	 * @return True if the parent parameter is valid for the current container.
	 */
	private boolean validateParent(GadgetContext context) {
		String container = context.getContainer();
		String parent = context.getParameter("parent");

		if (parent == null) {
			// If there is no parent parameter, we are still safe because no
			// dependent code ever has to trust it anyway.
			return true;
		}

		List<Object> parents = containerConfig.getList(container,
				"gadgets.parent");
		if (parents.isEmpty()) {
			// Allow all.
			return true;
		}

		// We need to check each possible parent parameter against this regex.
		for (Object pattern : parents) {
			if (Pattern.matches(pattern.toString(), parent)) {
				return true;
			}
		}

		return false;
	}
}
