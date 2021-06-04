# Funny Farm CLI
This a command line tool for talking to funny farm's api server. This requires a config.json file that contains the following:

```
{
    "env-name":{
        "label":"environment name",
        "url":"url for http requests",
        "username":"user",
        "password":"pass"
    }
}
```

You can define as many environments as you want. You just call it with the --env flag to switch between the endpoints. 