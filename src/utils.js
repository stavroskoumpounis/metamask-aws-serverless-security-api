const AWS = require('aws-sdk');
const dynamo = new AWS.DynamoDB();
const dynamoClient = new AWS.DynamoDB.DocumentClient();
const cognitoidentity = new AWS.CognitoIdentity();
const crypto = require('crypto');
const {ethers} = require('ethers');

const getNonce = (address) => {
  const params = {
    Statement: `SELECT "nonce" 
      FROM "${process.env.USERTABLE_NAME}" WHERE "address"='${address}'`,
  };
  return dynamo.executeStatement(params).promise();
};

const updateNonce = (address) => {
  const nonce = crypto.randomBytes(16).toString('hex');
  const params = {
    TableName: process.env.USERTABLE_NAME,
    Key: {
      address,
    },
    UpdateExpression: 'set nonce = :n',
    ExpressionAttributeValues: {
      ':n': nonce,
    },
    ReturnValues: 'ALL_NEW',
  };
  return dynamoClient.update(params).promise();
};

const getIdToken = (address) => {
  const param = {
    IdentityPoolId: process.env.IDENTITY_POOL_ID,
    Logins: {},
  };
  param.Logins[process.env.DEVELOPER_PROVIDER_NAME] = address;
  return cognitoidentity.getOpenIdTokenForDeveloperIdentity(param).promise();
};

const getCredentials = (identityId, cognitoOpenIdToken) => {
  const params = {
    IdentityId: identityId,
    Logins: {},
  };
  params.Logins['cognito-identity.amazonaws.com'] = cognitoOpenIdToken;
  return cognitoidentity.getCredentialsForIdentity(params).promise();
};

const validateSig = async (address, signature, nonce) => {
  const message = `Welcome message, nonce: ${nonce}`;
  const hash = ethers.utils.id(message);
  const signing_address = await ethers.utils.verifyMessage(hash, signature);
  return signing_address.toLowerCase() === address.toLowerCase();
};

module.exports = {
  getIdToken,
  getNonce,
  getCredentials,
  updateNonce,
  validateSig,
};
