
import boto3
from datetime import datetime
import os
import sys
import time
import json

def lambda_handler(context,event):
    
    response= getLogEvents(event)
    emailIamAuditReport(response)


def getLogEvents(event):
    return   "USER LOGGED INTO CONSOLE"

    
def emailIamAuditReport(event_report):
    sns= boto3.client('sns')
    response = sns.publish(
    TopicArn='arn:aws:sns:eu-west-1:******:IamCrossAccountUsersAuditTopic',
    Message= event_report,
    Subject="USER LOGIN EVENT IN SANDPIT ACCOUNT",
)   
        


