
import SQS from "aws-sdk/clients/sqs.js";
const sqs = new SQS();

//import split from "split-array"

export async function lambdaHandler(event) {
    let messagesSent
    try {

        messagesSent = await createIssuesList(event)

    }catch(error){
        return formatError(error)
    }
    return formatResponse(messagesSent);
}

async function createIssuesList(event) {
    let result = {};
    let messagesSent = []

    let additionalFields = {
        watch_name: event.watch_name,
        policy_name: event.policy_name
    }

    // combine 10 issue in the 'result', then create an array of batches of 10 issues and send it as a body

    try {
        for (let i = 0; i < event.issues.length; i++) {
            let issue = event.issues[i]
            result = {
                ...issue,
                ...additionalFields
            }

            let messageInfo = await sendSQSmessage(result)
            messagesSent.push({
                message: JSON.stringify(messageInfo)
            });
            console.log(messageInfo)
        }

    } catch (ex) {
        console.error('Error parsing API call body: ', ex);
    }

    return messagesSent;
}

async function sendSQSmessage(result){
    //let queueURL = process.env.SQS_QUEUE_URL;
    let queueURL = "https://sqs.us-west-1.amazonaws.com/096302395721/XraySourceQueue.fifo"

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

    return await sqs.sendMessage(params).promise()
}

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
    console.error(response)
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
    console.log(response)
    return response
}