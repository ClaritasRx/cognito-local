import { beforeEach, describe, expect, it, type MockedObject } from "vitest";
import { newMockCognitoService } from "../__tests__/mockCognitoService";
import { newMockTokenGenerator } from "../__tests__/mockTokenGenerator";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import type { CognitoService, UserPoolService } from "../services";
import type { TokenGenerator } from "../services/tokenGenerator";
import {
  GetTokensFromRefreshToken,
  type GetTokensFromRefreshTokenTarget,
} from "./getTokensFromRefreshToken";

describe("GetTokensFromRefreshToken target", () => {
  let getTokensFromRefreshToken: GetTokensFromRefreshTokenTarget;

  let mockUserPoolService: MockedObject<UserPoolService>;
  let mockCognitoService: MockedObject<CognitoService>;
  let mockTokenGenerator: MockedObject<TokenGenerator>;

  const userPoolClient = TDB.appClient();

  beforeEach(() => {
    mockUserPoolService = newMockUserPoolService();
    mockCognitoService = newMockCognitoService(mockUserPoolService);
    mockTokenGenerator = newMockTokenGenerator();

    mockCognitoService.getAppClient.mockResolvedValue(userPoolClient);

    getTokensFromRefreshToken = GetTokensFromRefreshToken({
      cognito: mockCognitoService,
      tokenGenerator: mockTokenGenerator,
    });
  });

  it("returns new tokens when given a valid refresh token", async () => {
    const existingUser = TDB.user();
    existingUser.RefreshTokens.push("valid-refresh-token");

    mockUserPoolService.getUserByRefreshToken.mockResolvedValue(existingUser);
    mockUserPoolService.listUserGroupMembership.mockResolvedValue(["group1"]);
    mockTokenGenerator.generate.mockResolvedValue({
      AccessToken: "new-access-token",
      IdToken: "new-id-token",
      RefreshToken: "new-refresh-token",
    });

    const result = await getTokensFromRefreshToken(TestContext, {
      ClientId: userPoolClient.ClientId,
      RefreshToken: "valid-refresh-token",
    });

    expect(result).toEqual({
      AuthenticationResult: {
        AccessToken: "new-access-token",
        IdToken: "new-id-token",
        TokenType: "Bearer",
      },
    });

    expect(mockTokenGenerator.generate).toHaveBeenCalledWith(
      TestContext,
      existingUser,
      ["group1"],
      userPoolClient,
      undefined,
      "RefreshTokens",
    );
  });

  it("throws NotAuthorizedError when refresh token is invalid", async () => {
    mockUserPoolService.getUserByRefreshToken.mockResolvedValue(null);

    await expect(
      getTokensFromRefreshToken(TestContext, {
        ClientId: userPoolClient.ClientId,
        RefreshToken: "invalid-token",
      }),
    ).rejects.toThrow("User not authorized");
  });

  it("throws NotAuthorizedError when client is not found", async () => {
    mockCognitoService.getAppClient.mockResolvedValue(null);

    await expect(
      getTokensFromRefreshToken(TestContext, {
        ClientId: "unknown-client",
        RefreshToken: "some-token",
      }),
    ).rejects.toThrow("User not authorized");
  });

  it("throws InvalidParameterError when ClientId is missing", async () => {
    await expect(
      getTokensFromRefreshToken(TestContext, {
        ClientId: "",
        RefreshToken: "some-token",
      }),
    ).rejects.toThrow("Missing required parameter");
  });

  it("throws InvalidParameterError when RefreshToken is missing", async () => {
    await expect(
      getTokensFromRefreshToken(TestContext, {
        ClientId: userPoolClient.ClientId,
        RefreshToken: "",
      }),
    ).rejects.toThrow("Missing required parameter");
  });

  it("passes ClientMetadata to token generator", async () => {
    const existingUser = TDB.user();
    existingUser.RefreshTokens.push("valid-refresh-token");

    mockUserPoolService.getUserByRefreshToken.mockResolvedValue(existingUser);
    mockUserPoolService.listUserGroupMembership.mockResolvedValue([]);
    mockTokenGenerator.generate.mockResolvedValue({
      AccessToken: "new-access-token",
      IdToken: "new-id-token",
      RefreshToken: "new-refresh-token",
    });

    await getTokensFromRefreshToken(TestContext, {
      ClientId: userPoolClient.ClientId,
      RefreshToken: "valid-refresh-token",
      ClientMetadata: { key: "value" },
    });

    expect(mockTokenGenerator.generate).toHaveBeenCalledWith(
      TestContext,
      existingUser,
      [],
      userPoolClient,
      { key: "value" },
      "RefreshTokens",
    );
  });
});
