# CloudTrail Console Actions

Problem: CloudTrail signal to noise ratio is too noisy for a human to understand. This Lambda's goal is to find actionable events and alert/log them.

<img src="docs/assets/flow-diagram-2021-05-14.png" alt="flow-diagram-2021-05-14" style="zoom:50%;" />

## Examples

[Event](https://app.slack.com/block-kit-builder/T4BH42T2M#%7B%22blocks%22:%5B%7B%22type%22:%22section%22,%22text%22:%7B%22type%22:%22mrkdwn%22,%22text%22:%22*PutUserPolicy*%20-%20iam.amazonaws.com%22%7D%7D,%7B%22type%22:%22context%22,%22elements%22:%5B%7B%22type%22:%22mrkdwn%22,%22text%22:%22:maple_leaf:%20NON-PRD%22%7D,%7B%22type%22:%22mrkdwn%22,%22text%22:%22john.doe@example.com%22%7D,%7B%22type%22:%22mrkdwn%22,%22text%22:%22%3Chttps://console.aws.amazon.com/cloudtrail/home?region=%25s#/events?EventId=404956a8-8b3a-400e-a180-5b0659d77403%7C2021-05-14T19:03:40Z%3E%22%7D%5D%7D%5D%7D) in Slack

<img align="left" src="docs/assets/image-20210514145815015.png" alt="image-20210514145815015" style="zoom:50%;" />

Event in CloudWatch

```
{
  "account_id": "123456789012",
  "event_id": "ec20d295-2332-4871-9a0c-0f3193119eb6",
  "event_name": "PutUserPolicy",
  "event_source": "iam.amazonaws.com",
  "event_time": "2021-05-14T19:03:40Z",
  "level": "info",
  "msg": "Event",
  "principal": "AIDA123456789EXAMPLE:john.doe@example.com",
  "time": "2021-05-14T19:18:19Z",
  "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36",
  "user_name": "john.doe@example.com"
}
```


## Environment Reference

The following environmental variables are supported:

* `SLACK_NAME` - (Optional) Specifies the name of the default account events are from.
* `SLACK_CHANNEL` - (Optional) Specifies the Slack Channel to publish events
* `SLACK_WEBHOOK` - (Optional) Specifies the webhook URL to send events to if not set only logs will be emitted.
* `SLACK_NAME_${AWS_ACCOUNT_NUMBER}` - (Optional)  Specifies the name of the account specific event.

*Note:* You can uses Slack Emoji's in `SLACK_NAME` and `SLACK_NAME_*` by using the standard `:maple_leaf:` designation.

