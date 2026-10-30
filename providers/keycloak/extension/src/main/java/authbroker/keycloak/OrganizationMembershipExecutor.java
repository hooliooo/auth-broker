package authbroker.keycloak;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.OrganizationModel;
import org.keycloak.models.UserModel;
import org.keycloak.organization.OrganizationProvider;
import org.keycloak.representations.idm.ClientPolicyExecutorConfigurationRepresentation;
import org.keycloak.services.clientpolicy.ClientPolicyContext;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.context.AbstractTokenResponseContext;
import org.keycloak.services.clientpolicy.context.TokenRefreshResponseContext;
import org.keycloak.services.clientpolicy.executor.ClientPolicyExecutorProvider;

/**
 * Refuses to issue or refresh a token unless it names exactly one site the user is a
 * member of.
 *
 * <p>A site is a Keycloak organization; the hub requests it with the dynamic scope
 * {@code organization:<alias>}. Keycloak on its own would leave the organization out of a
 * non-member's token instead of refusing it. This executor runs once the tokens are built, on
 * every authorization code exchange and every refresh, and refuses when:
 *
 * <ul>
 *   <li>no {@code organization:<alias>} scope, the wildcard {@code organization:*}, the bare
 *       {@code organization} scope, or more than one organization is requested;
 *   <li>the organization does not exist or is disabled;
 *   <li>the user is not a member of exactly that organization;
 *   <li>a refresh names a different organization than its refresh token was issued for.
 * </ul>
 *
 * <p>Keycloak 26.8 already refuses a non-member at the authorization request; this executor
 * adds the refresh-time checks (membership removed or organization disabled since sign-in, a
 * switched organization) and the scope rules.
 *
 * Refusals are standard OAuth errors ({@code invalid_scope}, {@code access_denied}), so the hub
 * can tell "not a member" from "Keycloak is down".
 */
public class OrganizationMembershipExecutor
    implements ClientPolicyExecutorProvider<ClientPolicyExecutorConfigurationRepresentation> {

  /** Prefix of the dynamic organization scope. */
  private static final String SCOPE_PREFIX = "organization:";

  /** The request's Keycloak session. */
  private final KeycloakSession session;

  /** Checks the requests of {@code session}. */
  OrganizationMembershipExecutor(KeycloakSession session) {
    this.session = session;
  }

  @Override
  public String getProviderId() {
    return OrganizationMembershipExecutorFactory.PROVIDER_ID;
  }

  @Override
  public void executeOnEvent(ClientPolicyContext context) throws ClientPolicyException {
    switch (context.getEvent()) {
      case TOKEN_RESPONSE -> check((AbstractTokenResponseContext) context, null);
      case TOKEN_REFRESH_RESPONSE -> {
        TokenRefreshResponseContext refresh = (TokenRefreshResponseContext) context;
        check(refresh, refresh.getParams().getFirst("refresh_token"));
      }
      default -> {}
    }
  }

  /**
   * Refuses the tokens being issued in {@code context} unless they name one membership; on a
   * refresh, also unless they name the organization {@code refreshToken} was issued for.
   */
  private void check(AbstractTokenResponseContext context, String refreshToken)
      throws ClientPolicyException {
    var clientSessionContext = context.getAccessTokenResponseBuilder().getClientSessionCtx();
    AuthenticatedClientSessionModel clientSession = clientSessionContext.getClientSession();
    UserModel user = clientSession.getUserSession().getUser();

    String alias = organizationAlias(clientSessionContext.getScopeString());
    if (refreshToken != null && !alias.equals(organizationAlias(scopeOf(refreshToken)))) {
      throw new ClientPolicyException("invalid_scope", "a session cannot switch sites");
    }

    OrganizationProvider organizations = session.getProvider(OrganizationProvider.class);
    OrganizationModel organization =
        organizations == null || !organizations.isEnabled() ? null : organizations.getByAlias(alias);
    if (organization == null || !organization.isEnabled()) {
      throw new ClientPolicyException("access_denied", "the site is unknown or disabled");
    }
    if (!organization.isMember(user)) {
      throw new ClientPolicyException("access_denied", "the user is not a member of the site");
    }
  }

  /** The one organization alias {@code scopes} name, or a refusal if it is not exactly one. */
  private static String organizationAlias(String scopes) throws ClientPolicyException {
    List<String> requested =
        Arrays.stream(scopes == null ? new String[0] : scopes.split(" "))
            .filter(scope -> scope.equals("organization") || scope.startsWith(SCOPE_PREFIX))
            .toList();
    if (requested.size() != 1
        || !requested.get(0).startsWith(SCOPE_PREFIX)
        || requested.get(0).equals(SCOPE_PREFIX + "*")) {
      throw new ClientPolicyException(
          "invalid_scope", "exactly one organization:<alias> scope is required");
    }
    return requested.get(0).substring(SCOPE_PREFIX.length());
  }

  /**
   * The {@code scope} claim of {@code refreshToken}. Read without verifying the signature:
   * Keycloak has verified the token before it builds the response this executor checks.
   */
  private static String scopeOf(String refreshToken) throws ClientPolicyException {
    try {
      String payload = refreshToken.split("\\.")[1];
      JsonNode claims =
          new ObjectMapper()
              .readTree(new String(Base64.getUrlDecoder().decode(payload), StandardCharsets.UTF_8));
      return claims.path("scope").asText(null);
    } catch (Exception e) {
      throw new ClientPolicyException("invalid_grant", "unreadable refresh token");
    }
  }
}
