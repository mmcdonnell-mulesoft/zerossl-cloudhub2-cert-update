#!/usr/bin/env bash

# Client ID Variable
CID="c78633e2d086486283e7bbc813428293"
# Client Secret Variable
CSECRET="f7128C1E705f46A9b2C1437B8Df8e79e"

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
               -o | --orgid
               -p | --private-space name
               -h | --help"
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



##############################################
## GETOPT VARIABLES + ARGUMENT PARSING END  ##
##############################################

echo "Updating Org: ${ORGID}"

# constants
TLSCNAME="prod-int-ext-combined"
BASEURI="https://anypoint.mulesoft.com/"
TOKENURI="${BASEURI}/accounts/api/v2/oauth2/token"
MEURI="${BASEURI}/accounts/api/profile"
ORGSURI="${BASEURI}/accounts/api/organizations"
PSALLURI="${BASEURI}/runtimefabric/api/organizations/${ORGID}/privatespaces"

echo "Getting our auth token for Client: ${CID}"
FULLTOKEN=$(curl -s -X POST -d "client_id=${CID}&client_secret=${CSECRET}&grant_type=client_credentials" ${TOKENURI})
TOKEN=$(echo ${FULLTOKEN} | jq -r .access_token)

echo "Getting private space: $PSNAME"
PSSPACES=$(curl -s ${PSALLURI} -H "Accept: application/json" -H "Authorization: Bearer ${TOKEN}")

# Get Private Space ID
PSID=$(echo ${PSSPACES} | jq -r ".content | map(select(.name == \"${PSNAME}\")) | first | .id")
PSURI="${PSALLURI}/{$PSID}"
TLSALLURI="${PSURI}/tlsContexts"

# My spaces will only have 1 context outside of default. We'll be cool with that assumption for now.
echo "Getting TLS Context ID: ${TLSCNAME}"
TLSCONTEXTS=$(curl -s ${TLSALLURI} -H "Accept: application/json" -H "Authorization: Bearer ${TOKEN}")
TLSCONTEXTID=$(echo ${TLSCONTEXTS} | jq -r ". | map(select(.name == \"${TLSCNAME}\")) | first | .id")
TLSURI="${TLSALLURI}/${TLSCONTEXTID}"
TLS_TO_UPDATE=$(curl -s ${TLSURI} -H "Accept: application/json" -H "Authorization: Bearer ${TOKEN}")

echo ${TLS_TO_UPDATE}