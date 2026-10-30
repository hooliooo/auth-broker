package authbroker.keycloak;

import java.util.List;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.clientpolicy.executor.ClientPolicyExecutorProvider;
import org.keycloak.services.clientpolicy.executor.ClientPolicyExecutorProviderFactory;

/** Registers {@link OrganizationMembershipExecutor} as client policy executor {@value #PROVIDER_ID}. */
public class OrganizationMembershipExecutorFactory implements ClientPolicyExecutorProviderFactory {

  /** The executor's id in client policy profiles. */
  public static final String PROVIDER_ID = "organization-membership";

  @Override
  public ClientPolicyExecutorProvider create(KeycloakSession session) {
    return new OrganizationMembershipExecutor(session);
  }

  @Override
  public void init(Config.Scope config) {}

  @Override
  public void postInit(KeycloakSessionFactory factory) {}

  @Override
  public void close() {}

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public String getHelpText() {
    return "Refuses tokens unless they name exactly one organization (site) the user is a member of.";
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return List.of();
  }
}
