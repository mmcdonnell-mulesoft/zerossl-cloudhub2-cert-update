#!/usr/bin/env bash

# Client ID Variable
CID="c78633e2d086486283e7bbc813428293"
# Client Secret Variable
CSECRET="f7128C1E705f46A9b2C1437B8Df8e79e"

#Zero SSL API Key
ZSSLAPIKEY="76f0930e6c61d516e761396a7ca96727"

##############################################
## GETOPT VARIABLES + ARGUMENT PARSING START##
##############################################

# Initializing other variables that will be taking in via getopt
unset -v ORGID
unset -v PSNAME

# Arguments for script
LONG_ARGS="orgid:,private-space:,help"
SHORT_ARGS="o:,p:,h"


# Help Function
help()
{
    echo "Based on standards I found on the internet - MPM"
    echo "Usage: ${0}
               -o | --orgid           Org Id
               -p | --private-space   Private Space Name
               -h | --help            Help Menu"
    exit 2
}

OPTS=$(getopt --options ${SHORT_ARGS} --longoptions ${LONG_ARGS} -- "$@")
eval set -- "${OPTS}"
while :
do
  case "$1" in
    -o | --orgid )
        ORGID="$2"
        shift 2
        ;;
    -p | --private-space )
        PSNAME="$2"
        shift 2
        ;;
    -h | --help )
      help
      ;;
    --)
      shift;
      break
      ;;
    *)
      echo "Unexpected option: $1"
      help
      ;;
  esac
done

if [ -z "${ORGID}" ] || [ -z "${PSNAME}" ]; then
  echo "Missing argument!"
  help
fi

echo "Updating Org: ${ORGID} and Private Space: ${PSNAME}"

##############################################
## GETOPT VARIABLES + ARGUMENT PARSING END  ##
##############################################



# constants

CERTCN="global.mulesoftplatform.com"
TMPCERTPATH="/tmp/${CERTCN}.pem"
PRIVATEKEYPATH="/tmp/${CERTCN}.private.key"
CSRPATH="/tmp/${CERTCN}.csr"

ZSSLBASE="https://api.zerossl.com"
ZSSLCERTURI="${ZSSLBASE}/certificates?access_key=${ZSSLAPIKEY}"
ZSSLVERIFYURI="${ZSSLBASE}/validation/csr?access_key=${ZSSLAPIKEY}"


TLSCNAME="prod-int-ext-combined"
APOINTBASE="https://anypoint.mulesoft.com/"
TOKENURI="${APOINTBASE}/accounts/api/v2/oauth2/token"
MEURI="${APOINTBASE}/accounts/api/profile"
ORGSURI="${APOINTBASE}/accounts/api/organizations"
PSALLURI="${APOINTBASE}/runtimefabric/api/organizations/${ORGID}/privatespaces"

echo "Cleaning up /tmp"
rm -fv "/tmp/${CERTCN}*"

# echo "Validating existing cert exists"
# This will download the cert. Doesn't look like we need to.
# </dev/null openssl s_client -connect ${CERTCN}:443 -servername ${CERTCN} | openssl x509 > ${TMPCERTPATH}


# echo "Getting our auth token for Client: ${CID}"
# FULLTOKEN=$(curl -s -X POST -d "client_id=${CID}&client_secret=${CSECRET}&grant_type=client_credentials" ${TOKENURI})
# TOKEN=$(echo ${FULLTOKEN} | jq -r .access_token)

# echo "Getting private space: $PSNAME"
# PSSPACES=$(curl -s ${PSALLURI} -H "Accept: application/json" -H "Authorization: Bearer ${TOKEN}")

# # Get Private Space ID
# PSID=$(echo ${PSSPACES} | jq -r ".content | map(select(.name == \"${PSNAME}\")) | first | .id")
# PSURI="${PSALLURI}/{$PSID}"
# TLSALLURI="${PSURI}/tlsContexts"

# # My spaces will only have 1 context outside of default. We'll be cool with that assumption for now.
# echo "Getting TLS Context ID: ${TLSCNAME}"
# TLSCONTEXTS=$(curl -s ${TLSALLURI} -H "Accept: application/json" -H "Authorization: Bearer ${TOKEN}")

# TLSCONTEXTID=$(echo ${TLSCONTEXTS} | jq -r ". | map(select(.name == \"${TLSCNAME}\")) | first | .id")
# echo "  ID: ${TLSCONTEXTID}"
# TLSURI="${TLSALLURI}/${TLSCONTEXTID}"

# echo "Validating existing TLS"
# TLS_TO_UPDATE=$(curl -s ${TLSURI} -H "Accept: application/json" -H "Authorization: Bearer ${TOKEN}")

# echo ${TLS_TO_UPDATE}

# 

ZSSLCERTS=$(curl -s ${ZSSLCERTURI} -H "Content-Type: application/json" | jq -r ".results | map(select(.common_name == \"${CERTCN}\"))")
NEWCERT=$(echo ${ZSSLCERTS} | jq -r ". | map(select(.status == \"draft\")) | unique | if length == 1 then .[0] else empty end")
if [ -z "${NEWCERT}" ]; then
  echo "Creating CSR for ${CERTCN}!"
  openssl req -new -nodes -out ${CSRPATH} -keyout ${PRIVATEKEYPATH} -newkey rsa:2048 -config <(
cat <<-END
[req]
default_bits = 2048
prompt = no
req_extensions = req_ext
distinguished_name = dn

[ dn ]
C=US
ST=Illinois
L=Chicago
O=MuleSoft
OU=Solution Engineering
emailAddress=michael.mcdonnell@salesforce.com
CN = ${CERTCN}

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = int.global.mulesoftplatform.com
DNS.2 = primary.mulesoftplatform.com
DNS.3 = int.primary.mulesoftplatform.com
DNS.4 = dr.mulesoftplatform.com
DNS.5 = int.dr.mulesoftplatform.com
END
) 2>/dev/null

  CSR="{\"csr\": \"$(cat ${CSRPATH} | awk '{printf "%s\\n", $0}')\"}"
  VALIDCSR=$(curl -s -X POST -H "Content-Type: application/json" -d "${CSR}" ${ZSSLVERIFYURI}) 
  if [ "true" != "$(echo ${VALIDCSR} | jq -r '.valid')" ]; then
    echo "Bad CSR! Do not submit!"
    echo ${VALIDCSR}
    exit 1
  fi

  echo "CSR is valid! Moving forward with submitting update request!"

  NEWCERTDTL=$( echo "{
  \"certificate_domains\": \"${CERTCN},int.${CERTCN},primary.mulesoftplatform.com,int.primary.mulesoftplatform.com,dr.mulesoftplatform.com,int.dr.mulesoftplatform.com\",
  \"certificate_csr\": \"$(cat ${CSRPATH} | awk '{printf "%s\\n", $0}')\",
  \"certificate_validity_days\": 90,
  \"strict_domains\": 1
}" | jq -c '.');

  echo "${NEWCERTDTL}"
# 
  NEWCERT=$(curl -s -X POST -H "Content-Type: application/json" -d "${NEWCERTDTL}" ${ZSSLCERTURI})
  if [ "true" != "$(echo ${NEWCERT} | jq -r '.success')" ]; then
    echo "Bad Cert! Do not validate!"
    echo ${NEWCERT}
    exit 1
  fi
fi;
NEWCERTID=$(echo ${NEWCERT} | jq -r ".id")

echo "DEBUG: Check for the existance of a record BEFORE creation - we should just challenge if that's the case"

# echo "Cert was created. Time to create CNAME Records!"
# BATCH=$(jq --null-input '{Changes:[]}')
# DOMAINS=$(echo ${NEWCERT} | jq -r ".validation.other_methods | keys[]")
# for FQDN in ${DOMAINS}
# do
#   KEY=$(echo ${NEWCERT} | jq -r ".validation.other_methods.\"${FQDN}\".cname_validation_p1")
#   VAL=$(echo ${NEWCERT} | jq -r ".validation.other_methods.\"${FQDN}\".cname_validation_p2")
#   RECORD=$(jq --null-input --arg hostname "${KEY}" --arg endpoint "${VAL}" '{"Action":"CREATE","ResourceRecordSet":{"Name":$hostname,"Type":"CNAME","TTL":60,"ResourceRecords":[{"Value":$endpoint}]}}')
#   BATCH=$(echo ${BATCH} | jq ".Changes += [${RECORD}]")
# done

# echo "CNAME records pre-generated - now to push to Route53"
# MPZONEID=$(aws route53 list-hosted-zones | jq -r ".HostedZones | map(select(.Name == \"mulesoftplatform.com.\")) | first | .Id")
# aws route53 change-resource-record-sets --hosted-zone-id "${MPZONEID}" --change-batch "${BATCH}"

# echo "I'm sleeping because I'm lazy (instead of checking to make sure my AWS R53 entries are done"
# sleep 10

# echo "Testing Challenge"
# # https://zerossl.com/documentation/api/verify-domains/
# ZSSLCHALLENGEURI="${ZSSLBASE}/certificates/${NEWCERTID}/challenges?access_key=${ZSSLAPIKEY}"
# curl -s -X POST -H "Content-Type: application/json" -d "{\"validation_method\": \"CNAME_CSR_HASH\"}" ${ZSSLCHALLENGEURI}
#RETURNS {
#   "id": "4ddc81628ed9d163de28c4f743a06f08",
#   "type": "3",
#   "common_name": "global.mulesoftplatform.com",
#   "additional_domains": "int.global.mulesoftplatform.com,primary.mulesoftplatform.com,int.primary.mulesoftplatform.com,dr.mulesoftplatform.com,int.dr.mulesoftplatform.com",
#   "created": "2024-01-08 23:49:58",
#   "expires": "2024-04-07 00:00:00",
#   "status": "pending_validation", <--- THIS IS WHAT WE NEED TO SEE?

# aws route53 change-resource-record-sets --hosted-zone-id "${MPZONEID}" --change-batch "{\"Changes\":[{\"Action\":\"DELETE\",\"ResourceRecordSet\":{\"Name\":\"${KEY}.\",\"Type\":\"CNAME\",\"TTL\":300,\"ResourceRecords\":[{\"Value\":\"${VAL}.\"}]}}]}"

# TODO: Tomorrow upload the good cert to CH2.0!