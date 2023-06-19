# DO NOT USE (yet) !

# Cloudformation

A little 'chicken and egg' - you need to bootstrap the user using the `bootstrap-user.yaml` template.  This will create a user with access to '*', i.e. all, resources.  Once this has been completed, it will give you the ARN on the outputs page under `OcspAccessRole`.

Copy the value of the `OcspAccessRole` output, and use it as an input to the `boostrap-db-access.yaml` template.  This will create a policy allowing access to the dynamoDB table in the other account (i.e. the one where certsquirt is creating entries in the db).

Once that has finished executing, it will output the Role ARN it has created, under the key `OcspAccessRole`.  Copy this value, and then edit the `bootstrap-user.yaml` template and change the following:

```
            # Resource: !Ref AccessRoleName
            Resource: '*'  # change this once you know the rolename!
```

so that it is more tightly scoped, such as this:

```
            Resource: !Ref AccessRoleName
            # Resource: '*'  # change this once you know the rolename!
```

Then, run the template again and use the value from `OcspAccessRole` as an input for the variable `AccessRoleName`.  Once this appears correct, uncomment the block for `OcspRole` in the template and run once again.

