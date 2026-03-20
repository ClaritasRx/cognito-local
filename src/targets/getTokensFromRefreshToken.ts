import { InvalidParameterError, NotAuthorizedError } from "../errors";
import type { Services } from "../services";
import type { Context } from "../services/context";
import type { Target } from "./Target";

/**
 * GetTokensFromRefreshToken is a newer Cognito API used by Amplify v6 for token refresh.
 * It does the same thing as InitiateAuth with REFRESH_TOKEN_AUTH but with a flatter request shape.
 *
 * AWS docs: https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_GetTokensFromRefreshToken.html
 */

interface GetTokensFromRefreshTokenRequest {
  ClientId: string;
  RefreshToken: string;
  ClientSecret?: string;
  DeviceKey?: string;
  ClientMetadata?: Record<string, string>;
}

interface GetTokensFromRefreshTokenResponse {
  AuthenticationResult: {
    AccessToken: string;
    IdToken: string;
    ExpiresIn?: number;
    RefreshToken?: string;
    TokenType?: string;
  };
}

export type GetTokensFromRefreshTokenTarget = Target<
  GetTokensFromRefreshTokenRequest,
  GetTokensFromRefreshTokenResponse
>;

type GetTokensFromRefreshTokenServices = Pick<
  Services,
  "cognito" | "tokenGenerator"
>;

export const GetTokensFromRefreshToken =
  (services: GetTokensFromRefreshTokenServices): GetTokensFromRefreshTokenTarget =>
  async (ctx: Context, req) => {
    if (!req.ClientId) {
      throw new InvalidParameterError("Missing required parameter ClientId");
    }
    if (!req.RefreshToken) {
      throw new InvalidParameterError("Missing required parameter RefreshToken");
    }

    const userPool = await services.cognito.getUserPoolForClientId(
      ctx,
      req.ClientId,
    );
    const userPoolClient = await services.cognito.getAppClient(
      ctx,
      req.ClientId,
    );
    if (!userPoolClient) {
      throw new NotAuthorizedError();
    }

    const user = await userPool.getUserByRefreshToken(ctx, req.RefreshToken);
    if (!user) {
      throw new NotAuthorizedError();
    }

    const userGroups = await userPool.listUserGroupMembership(ctx, user);

    const tokens = await services.tokenGenerator.generate(
      ctx,
      user,
      userGroups,
      userPoolClient,
      req.ClientMetadata,
      "RefreshTokens",
    );

    return {
      AuthenticationResult: {
        AccessToken: tokens.AccessToken,
        IdToken: tokens.IdToken,
        TokenType: "Bearer",
      },
    };
  };
