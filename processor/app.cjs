const AWS = require('aws-sdk')
const sqs = new AWS.SQS();

exports.lambdaHandler = async (event) => {

    let additionalFields = {
        watch_name: event.watch_name,
        policy_name: event.policy_name
    }

    let messagesSent = []
    //let queueURL = process.env.SQS_QUEUE_URL;
    let queueURL = "https://sqs.us-west-1.amazonaws.com/096302395721/XraySourceQueue.fifo"

    try {
        for (let i = 0; i < event.issues.length; i++) {
            let issue = event.issues[i]
            let result = {
                ...issue,
                ...additionalFields
            }

            let params = {
                MessageAttributes: {
                    "MessageType": {
                        DataType: "String",
                        StringValue: "Issue received from JFrog Xray"
                    },
                },
                MessageBody: JSON.stringify(result),
                MessageDeduplicationId: Date.now().toString(),
                MessageGroupId: "XrayPayload",
                QueueUrl: queueURL
            };

            let queueRes = await sqs.sendMessage(params).promise();
            messagesSent.push({
                message: JSON.stringify(queueRes)
            });

        }
    } catch (error) {
        return formatError(error)
    }

    return formatResponse(messagesSent)
};

let formatError = function(error) {
    let response = {
        "statusCode": error.statusCode,
        "headers": {
            "Content-Type": "text/plain",
            "x-amzn-ErrorType": error.code
        },
        "isBase64Encoded": false,
        "body": error.code + ": " + error.message
    }
    return response
}

let formatResponse = function(body){
    let response = {
        "statusCode": 200,
        "headers": {
            "Content-Type": "application/json"
        },
        "isBase64Encoded": false,
        "multiValueHeaders": {
            "X-Custom-Header": ["My value", "My other value"],
        },
        "body": body
    }
    return response
}