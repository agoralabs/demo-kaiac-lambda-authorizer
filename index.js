const jwt = require('jsonwebtoken'); // Assurez-vous d'inclure jsonwebtoken dans votre package

exports.handler = async (event) => {
    const token = event.headers.Authorization;

    if (!token) {
        return generatePolicy('user', 'Deny', event.methodArn);
    }

    try {
        // Remplacez 'your-secret-key' par votre clé secrète JWT
        const decoded = jwt.verify(token, 'your-secret-key');
        return generatePolicy(decoded.sub, 'Allow', event.methodArn);
    } catch (error) {
        return generatePolicy('user', 'Deny', event.methodArn);
    }
};

// Fonction pour générer une politique IAM
const generatePolicy = (principalId, effect, resource) => {
    const authResponse = {};
    authResponse.principalId = principalId;

    if (effect && resource) {
        const policyDocument = {};
        policyDocument.Version = '2012-10-17'; // Version de la politique IAM
        policyDocument.Statement = [];
        const statementOne = {};
        statementOne.Action = 'execute-api:Invoke'; // Action de l'API Gateway
        statementOne.Effect = effect;
        statementOne.Resource = resource;
        policyDocument.Statement[0] = statementOne;
        authResponse.policyDocument = policyDocument;
    }

    // Retourne le principalId, utile pour l'audit
    authResponse.context = {
        user: principalId
    };

    return authResponse;
};
