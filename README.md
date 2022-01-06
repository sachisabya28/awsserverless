## _AWS SERVERLESS_

In order to implement serverless artitecture with AWS
we are implementing RESTAPI using Lambda, DynamoDB, API GAteway

## IAM credentials
*** 
Use valid aws crdentials
***

###### Setup AWS credentials locally using credentials . ######

```bash
aws configure
AWS Access Key ID [None]: Access_key_goes_here
AWS Secret Access Key [None]: Secret_Access_Key_goes_here
Default region name [None]: region
Default output format [None]: json
```
###### Installation Guide ######

```bash
git clone https://github.com/sachisabya28/awsserverless.git
npm install -g serverless
sls plugin install -n serverless-python-requirements
sls deploy 
```
**If you want to deploy local Lambda function changes directly without packaging 
them again using above commands.**

```bash
sls deploy function -f <lambda_function_name>
```
###### Reference ######
```bash
https://www.serverless.com/framework/docs
https://boto3.amazonaws.com/v1/documentation/api/latest/index.html
https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Introduction.html
https://docs.aws.amazon.com/lambda/latest/dg/welcome.html
```
