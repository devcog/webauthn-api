!!!Do not use in production. This is a proof of concept and has known issues.!!!

This deployment is to run on GCP Cloudrun.
The following must be set as env vars in the cloudrun setup for this to work:
-  DB_URL={mongo_db_connection_string}
-  RP_ID={https://url_where_this_service_is_hosted}
-  EXPECTED_ORIGIN={https://expected_url_from_reqs}
-  NODE_ENV=production

Additionally, using Google Secret Manager we should store:
- TOKEN_SECRET={long_rand_value}
