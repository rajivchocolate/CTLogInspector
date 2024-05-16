import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import * as iam from 'aws-cdk-lib/aws-iam';
import { Rule, Schedule } from 'aws-cdk-lib/aws-events';
import { LambdaFunction } from 'aws-cdk-lib/aws-events-targets';
import * as lambdaEventSources from 'aws-cdk-lib/aws-lambda-event-sources';

export class CdkStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // S3 bucket for storing problematic log entries
    const s3Bucket = new s3.Bucket(this, 'FailedCTLBucket');

    // SQS Queue and DLQ
    const deadLetterQueue = new sqs.Queue(this, 'CTDeadLetterQueue');
    const sqsQueue = new sqs.Queue(this, 'CertificateTransparencyQueue', {
      deadLetterQueue: {
        queue: deadLetterQueue,
        maxReceiveCount: 3
      }
    });

    // DynamoDB tables
    const domainsTable = new dynamodb.Table(this, 'CertificateTransparency', {
      partitionKey: { name: 'domain', type: dynamodb.AttributeType.STRING },
    });

    const stateTable = new dynamodb.Table(this, 'CTLStateTable', {
      partitionKey: { name: 'url', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
    });

    // Lambda IAM role
    const lambdaRole = new iam.Role(this, 'LambdaExecutionRole', {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
    });
    lambdaRole.addToPolicy(new iam.PolicyStatement({
      resources: ['*'],
      actions: [
        'logs:*',
        'dynamodb:*',
        's3:*',
        'sqs:*'
      ],
    }));

    const totalShards = 100;  // Define the number of Lambda functions to process CT logs

    for (let i = 1; i <= totalShards; i++) {
      // Lambda function for each shard
      const ctProcessorLambda = new lambda.Function(this, `CTProcessorLambda${i}`, {
        runtime: lambda.Runtime.PYTHON_3_10,
        code: lambda.Code.fromAsset('./lambdas/processing_lambda.zip'),
        handler: 'lambda_handler',
        timeout: cdk.Duration.minutes(15),
        role: lambdaRole,
        environment: {
          STATE_TABLE: stateTable.tableName,
          DOMAINS_TABLE: domainsTable.tableName,
          SQS_QUEUE_URL: sqsQueue.queueUrl,
          S3_BUCKET: s3Bucket.bucketName,
          LAMBDA_SHARD_NUMBER: `${i}`
        }
      });

      // EventBridge rule to trigger each Lambda every 15.5 minutes
      const eventRule = new Rule(this, `CtLogProcessingRule${i}`, {
        schedule: Schedule.expression('rate(15 minutes 30 seconds)')
      });
      eventRule.addTarget(new LambdaFunction(ctProcessorLambda));

      // Grant necessary permissions
      domainsTable.grantReadWriteData(ctProcessorLambda);
      s3Bucket.grantWrite(ctProcessorLambda);
      sqsQueue.grantSendMessages(ctProcessorLambda);
    }

    // Lambda function for initializing state
    const ctlStateInitializer = new lambda.Function(this, 'CtlStateInitializer', {
      runtime: lambda.Runtime.PYTHON_3_10,
      code: lambda.Code.fromAsset('./lambdas/ct_state_tracker.zip'),
      handler: 'lambda_handler',
      environment: {
        STATE_TABLE: stateTable.tableName
      },
      role: lambdaRole
    });

    // Lambda function for processing domains from SQS queue
    const domainWriterLambda = new lambda.Function(this, 'DomainProcessorLambda', {
      runtime: lambda.Runtime.PYTHON_3_10,
      code: lambda.Code.fromAsset('./lambdas/ct_domain_ddb_Writer.py'),
      handler: 'lambda_handler',
      environment: {
        DOMAINS_TABLE: domainsTable.tableName,
      },
    });

    // Configure Lambda to be triggered by SQS queue
    domainWriterLambda.addEventSource(new lambdaEventSources.SqsEventSource(sqsQueue));

    // Grant SQS consume messages permission to domain writer Lambda
    sqsQueue.grantConsumeMessages(domainWriterLambda);
  }
}