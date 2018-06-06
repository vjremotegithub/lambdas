
import boto3
from datetime import datetime
import os
import sys
import time
import json

event_report=[]
def lambda_handler(context,event):
    
    role= 'arn:aws:iam::***:role/SandpitIamAuditRole'
    log_group= 'CloudTrail/sandpit-cloud-trail'
    dateInMilliSecondsNow=int((datetime.utcnow() - datetime(1970, 1, 1)).total_seconds() * 1000)
    #Subtract 30 mins
    halfAnHourBefore= dateInMilliSecondsNow - 1800000
    # Convert back to date
    #print datetime.utcfromtimestamp(dateInMilliSecondsNow//1000).replace(microsecond=dateInMilliSecondsNow%1000*1000)
    #print datetime.utcfromtimestamp(halfAnHourBefore//1000).replace(microsecond=halfAnHourBefore%1000*1000)
    
    startTime=halfAnHourBefore
    endTime=dateInMilliSecondsNow
    filterPattern= 'CreateUser'
    kwargs = {
         'logGroupName': log_group,
       # 'limit': 1000, #default 10000 - 1mb
       # 'nextToken': next_token,
       'startTime': startTime,
       'endTime':  endTime,
       'filterPattern': filterPattern,
       'interleaved': True
    }
    logEvents= getLogEvents(role,**kwargs)
    #print(logEvents[-1]) # Last event only
    print ("##########################################################################################")
    event_report.append("\n\n##########################################################################################")
    for event in logEvents:
        #print "Total Log Events: " + str(len (logEvents))
        #event_report.append (event['message'].rstrip())
        
        try:
                result = json.loads(event['message'])
                print ("=====================================")
                print (" USER CREATED BY ")
                print ("=====================================")
                print ("UserType: " + result['userIdentity']['type'])
                print ("Assumed Role ARN: " + result['userIdentity']['arn'])
                print ("SourceIPAddress: " + result['sourceIPAddress'])
                print ("UserAgent: " + result['userAgent'])
        
                print ("=====================================")
                print (" CREATED USER DETAILS ")
                print ("=====================================")
                print ("UserName: " + result['responseElements']['user']['userName'])
                print ("User ARN: " + result['responseElements']['user']['arn'])
                print ("Creation Date/Time: " + result['responseElements']['user']['createDate'])
                print ("##########################################################################################")
                
                event_report.append ("=====================================")
                event_report.append (" USER CREATED BY ")
                event_report.append ("=====================================")
                event_report.append ("UserType: " + result['userIdentity']['type'])
                event_report.append ("Assumed Role ARN: " + result['userIdentity']['arn'])
                event_report.append ("SourceIPAddress: " + result['sourceIPAddress'])
                event_report.append ("UserAgent: " + result['userAgent'])
        
                event_report.append ("=====================================")
                event_report.append (" CREATED USER DETAILS ")
                event_report.append ("=====================================")
                event_report.append ("UserName: " + result['responseElements']['user']['userName'])
                event_report.append ("User ARN: " + result['responseElements']['user']['arn'])
                event_report.append ("Creation Date/Time: " + result['responseElements']['user']['createDate'])
                event_report.append ("##########################################################################################")
        except Exception, e:
            print (e.message)
            
    emailIamAuditReport(event_report)
    del event_report[:]

def getLogEvents(roleName,**kwargs):
    session = role_arn_to_session(
            RoleArn=roleName,
            RoleSessionName='clodwatch_audit_session')
    cloudwatchLogsClient = session.client('logs')
    resp = cloudwatchLogsClient.filter_log_events(**kwargs)
    return resp['events'] 

    
def emailIamAuditReport(event_report):
    sns= boto3.client('sns')
    response = sns.publish(
    TopicArn='arn:aws:sns:eu-west-1:****:IamCrossAccountUsersAuditTopic',
    Message= '\n'.join(event_report),
    Subject="USER CREATED EVENT",
)   
        
def role_arn_to_session(**args):
    client = boto3.client('sts')
    response = client.assume_role(**args)
    print response
    return boto3.Session(
        aws_access_key_id=response['Credentials']['AccessKeyId'],
        aws_secret_access_key=response['Credentials']['SecretAccessKey'],
        aws_session_token=response['Credentials']['SessionToken'])

