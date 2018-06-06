
import boto3
from datetime import datetime
import os
import sys
import time



def lambda_handler(context,event):

            #roleList=[]
            #roleList.append(os.environ['Role1'])
            #roleList.append (os.environ['Role2'])
            #roleList.append (os.environ['Role3'])
            #for role in roleList:

                role= 'arn:aws:iam::******:role/SandpitIamAuditRole'
                log_group= 'CloudTrail/sandpit-cloud-trail'
                #next_token='NextToken'
                startTime=1527663600000
                endTime=1527675312817
                filterPattern= 'CreateUser'
                kwargs = {
                     'logGroupName': log_group,
                   # 'limit': 1000,#Default 10000 - 1mb
                   # 'nextToken': next_token,
                   #'startTime': startTime,
                   #'endTime':  endTime,
                   'filterPattern': filterPattern,
                   'interleaved': True
                }
                logEvents= getLogEvents(role,**kwargs)
                for event in logEvents:
                    
                    print "Total Log Events: " + str(len (logEvents))
                    print(event['message'].rstrip())



def getLogEvents(roleName,**kwargs):
    session = role_arn_to_session(
            RoleArn=roleName,
            RoleSessionName='clodwatch_audit_session')
    cloudwatchLogsClient = session.client('logs')
    resp = cloudwatchLogsClient.filter_log_events(**kwargs)
    return resp['events'] 

    
def emailIamAuditReport(sns_report):
    sns= boto3.client('sns')
    response = sns.publish(
    TopicArn='arn:aws:sns:eu-west-1:*******:IamCrossAccountUsersAuditTopic',
    Message= '\n'.join(sns_report),
    Subject="LIST OF IAM USERS CREATED ON: " + "{:%d.%m.%Y}".format(datetime.now()),
)   
        
def role_arn_to_session(**args):
    client = boto3.client('sts')
    response = client.assume_role(**args)
    print response
    return boto3.Session(
        aws_access_key_id=response['Credentials']['AccessKeyId'],
        aws_secret_access_key=response['Credentials']['SecretAccessKey'],
        aws_session_token=response['Credentials']['SessionToken'])

