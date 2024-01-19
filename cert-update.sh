#!/usr/bin/env bash


# TODO:
# 1. Revoke the old cert.
# 2. Allow for the creation of a new context with a name standard
# e.g. global-mulesoftplatform-com-context
#

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
function help()
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

##############################################
##                CONSTANTS                 ##
##############################################
# Anypoint Platform
CID=""
CSECRET=""
# URIs
APOINTBASE="https://anypoint.mulesoft.com/"
TOKENURI="${APOINTBASE}/accounts/api/v2/oauth2/token"
MEURI="${APOINTBASE}/accounts/api/profile"
ORGSURI="${APOINTBASE}/accounts/api/organizations"
PSALLURI="${APOINTBASE}/runtimefabric/api/organizations/${ORGID}/privatespaces"

# AWS
AWSR53PARENT="mulesoftplatform.com."
AWSR53ZONEID=$(aws route53 list-hosted-zones | jq --arg domain "${AWSR53PARENT}" -r '.HostedZones | map(select(.Name == $domain)) | first | .Id')
AWSR53RECORDS=$(aws route53 list-resource-record-sets --hosted-zone-id ${AWSR53ZONEID} | jq --arg domain "${AWSR53PARENT}" -r '.ResourceRecordSets | map(select(.Name != $domain))')
AWSR53CREATE='{"Action":"CREATE","ResourceRecordSet":{"Name":$hostname,"Type":"CNAME","TTL":5,"ResourceRecords":[{"Value":$endpoint}]}}'
AWSR53DELETE='{"Action":"DELETE","ResourceRecordSet":{"Name":$hostname,"Type":"CNAME","TTL":5,"ResourceRecords":[{"Value":$endpoint}]}}'
# AWS Route53 Record State
PENDING="PENDING"
INSYNC="INSYNC"

#Threshold for Cert
THRESHOLD=$(date +%s -d "+14 days")
TODAY=$(date +%s)

# ZeroSSL
ZSSLAPIKEY=""
# URIs
ZSSLBASE="https://api.zerossl.com"
ZSSLCERTURI="${ZSSLBASE}/certificates?access_key=${ZSSLAPIKEY}"
ZSSLVERIFYURI="${ZSSLBASE}/validation/csr?access_key=${ZSSLAPIKEY}"
# Cert Req Files
ZSSLCSR="request.csr"
ZSSLCSRCFG="request.cfg"
ZSSLPRIKEY="private.key"
# Zero SSL Cert State
ISSUED="issued"
DRAFT="draft"
PENDING="pending_validation"

##############################################
##              END CONSTANTS               ##
##############################################

##############################################
##                 GLOBALS                  ##
##############################################

TLSALLURI=""

##############################################
##               END GLOBALS                ##
##############################################

##############################################
##                FUNCTIONS                 ##
##############################################

function anypoint_get_tls_contexts(){
  local -n __RET=${1}
  local TLS_ARR=()
  local PSSPACES=$(curl -s ${PSALLURI} -H "Accept: application/json" -H "Authorization: Bearer ${TOKEN}")
  local PSID=$(echo ${PSSPACES} | jq -r ".content | map(select(.name == \"${PSNAME}\")) | first | .id")
  TLSALLURI="${PSALLURI}/{$PSID}/tlsContexts"
  local TLSCONTEXTS=$(curl -s ${TLSALLURI} -H "Accept: application/json" -H "Authorization: Bearer ${TOKEN}")

  for TLSC in $(echo "${TLSCONTEXTS}" | jq -r -c '.[] | @base64'); do
    local TLSC_DECRYPTED=$(echo "${TLSC}" | base64 --decode | jq -r '.')
    local TLSC_NAME=$(echo "${TLSC_DECRYPTED}" | jq -r '.name')
    local TLSC_CN=$(echo "${TLSC_DECRYPTED}" | jq -r '.keyStore.cn')
    if [[ ${TLSC_CN} != *"cloudhub.io"* ]]; then
      TLS_ARR+=("${TLSC_NAME}")
    fi
  done;

  prompt_choice CONTEXT 'Which TLS Context would you like to rotate?' "${TLS_ARR[@]}"
  __RET=$(echo "${TLSCONTEXTS}" | jq -r --arg tlsname "${CONTEXT}" '. | map(select(.name == $tlsname)) | unique | if length == 1 then .[0] else empty end')

  if [ -z "${__RET}" ]; then
    echo "ERROR! Couldn't find Context by name '${CONTEXT}'"
    echo ${TLSCONTEXTS}
    exit 1;
  fi

}
function anypoint_login() {
  local FULLTOKEN=$(curl -s -X POST -d "client_id=${CID}&client_secret=${CSECRET}&grant_type=client_credentials" ${TOKENURI})
  echo ${FULLTOKEN} | jq -r .access_token
}
function anypoint_update_context() {
  local CONTEXT=${1}
  local CERT=${2}

  local CONTEXT_NAME=$(echo ${CONTEXT} | jq -r '.name')
  local CONTEXT_ID=$(echo ${CONTEXT} | jq -r '.id')
  local CONTEXT_URI="${TLSALLURI}/${CONTEXT_ID}"

  local CERT_ID=$(echo ${CERT} | jq -r '.id')
  local CERT_NAME=$(echo ${CERT} | jq -r '.common_name')
  local CERT_CREATED=$(echo ${CERT} | jq -r '.created')

  # Converted from "today" to the day the cert was created. 
  local DIRSTRUCT="${CERT_NAME}/$(date -d "${CERT_CREATED}" +'%Y-%m-%d')"

  # TODO: This is specific to me.
  local PERMADIR="${HOME}/certs/${DIRSTRUCT}"
  local PKFILE="${PERMADIR}/${ZSSLPRIKEY}"

  if [ ! -d ${PERMADIR} ]; then
    echo "Error! ${PERMADIR} does not exist!"
    exit 1;
  fi

  if [ ! -f ${PKFILE} ]; then
    echo "Error! ${PKFILE} does not exist!"
    exit 1;
  fi;

  echo "  Updating ${CONTEXT_NAME} with ${CERT_NAME}"
  zssl_download_cert "${CERT_ID}" PEMDATA
  local CERTDATA="$(echo ${PEMDATA} | jq -r '."certificate.crt"')"
  local CAPTDATA="$(echo ${PEMDATA} | jq -r '."ca_bundle.crt"')"
  local PKEYDATA="$(cat ${PKFILE} | awk '{printf "%s\n", $0}')"
  # "keyPassphrase": "",
  local TLSCFG_JSON='{"tlsConfig": { "keyStore": {"source": "PEM","certificate": $cert,"certificateFileName": $certname,"key": $pkey,"keyFileName": $pkeyname,"capath": $capath,"capathFileName": $capathname}}}'
  local TLSCFG=$(jq --null-input --arg cert "${CERTDATA}" --arg certname "certificate.crt" --arg pkey "${PKEYDATA}" --arg pkeyname "${ZSSLPRIKEY}" --arg capath "${CAPTDATA}" --arg capathname "ca_bundle.crt" "${TLSCFG_JSON}")
  local CONTEXT_UPDATE=$(curl -s -X PATCH -H "Accept: application/json" -H "Content-Type: application/json" -H "Authorization: Bearer ${TOKEN}" -d "${TLSCFG}" ${CONTEXT_URI})
  # curl -X PATCH -H "Accept: application/json" -H "Content-Type: application/json" -H "Authorization: Bearer ${TOKEN}" -d "${TLSCFG}" ${CONTEXT_URI}
  if [ -z "$(echo ${CONTEXT_UPDATE} | jq -r '.id')" ]; then
    echo "Updating ${CONTEXT_NAME} failed!"
    echo "${CONTEXT_UPDATE}"
    exit 1;
  fi
}
function aws_r53_create_if_not_exists() {
  local CNAME=${1}
  local VALUE=${2}
  local -n CHANGE_ID=${3}

  #
  if [[ 1 > $(echo "${AWSR53RECORDS}" |  jq --arg fqdn "$(echo ${CNAME} | awk '{print tolower($0)}')." -r '. | map(select(.Name==$fqdn)) | length') ]]; then
    # We need to create
    local RECORD=$(jq --null-input --arg hostname "${CNAME}" --arg endpoint "${VALUE}" ${AWSR53CREATE})
    local BATCH=$(jq --null-input "{Changes:[${RECORD}]}")
    local CHANGE=$(aws route53 change-resource-record-sets --hosted-zone-id "${AWSR53ZONEID}" --change-batch "${BATCH}")
    CHANGE_ID=$(echo "${CHANGE}" | jq -r '.ChangeInfo.Id')

    echo "  New Record ${CNAME} added successfully!"
    AWSR53RECORDS=$(aws route53 list-resource-record-sets --hosted-zone-id ${AWSR53ZONEID} | jq --arg domain "${AWSR53PARENT}" -r '.ResourceRecordSets | map(select(.Name != $domain))')
  fi
}
function aws_r53_delete_if_exists() {
  local CNAME=${1}
  local VALUE=${2}
  #
  EXISTS=$(echo "${AWSR53RECORDS}" |  jq --arg fqdn "${CNAME}." -r '. | map(select(.Name==$fqdn)) | length')
  if [[ 0 < ${EXISTS} ]]; then
    # We need to create
    RECORD=$(jq --null-input --arg hostname "${CNAME}" --arg endpoint "${VALUE}" ${AWSR53DELETE})
    BATCH=$(jq --null-input "{Changes:[${RECORD}]}")
    CHANGE_ID=$(aws route53 change-resource-record-sets --hosted-zone-id "${AWSR53ZONEID}" --change-batch "${BATCH}" | jq -r '.ChangeInfo.Id')
    echo "  Record ${CNAME} Deleted successfully!"
    # We don't need to check on this change status
    AWSR53RECORDS=$(aws route53 list-resource-record-sets --hosted-zone-id ${AWSR53ZONEID} | jq --arg domain "${AWSR53PARENT}" -r '.ResourceRecordSets | map(select(.Name != $domain))')
  fi
}
function aws_r53_wait_for_propogation() {
  local CNAME=${1}
  local CHANGE_ID=${2}
  local CHANGE=$(aws route53 get-change --id "${CHANGE_ID}")
  local CHANGE_COUNTER=0
  while [ "${INSYNC}" != "${CHANGE_STATUS}" ]; do
    echo "  Waiting for new record (${CNAME}) to propagate. (Waiting: ${CHANGE_COUNTER}, Timeout 2 Minutes)"
    sleep 2;
    CHANGE=$(aws route53 get-change --id "${CHANGE_ID}")
    local CHANGE_STATUS=$(echo "${CHANGE}" | jq -r '.ChangeInfo.Status')
    CHANGE_COUNTER=$((CHANGE_COUNTER+1))
    if [ 60 -lt $CHANGE_COUNTER ]; then
      echo "Error - Propagation took too long. (Waiting: ${CHANGE_COUNTER})"
      echo ${CHANGE}
      exit 99
    fi
  done
  echo "  Record for ${CNAME} successfully propagated!"
}
function is_expiring_soon() {
  local __EXPIRATION=${1}
  echo $([[ (${__EXPIRATION} -ge ${TODAY} && ${__EXPIRATION} -le ${THRESHOLD}) || (${__EXPIRATION} < ${TODAY}) ]])
}

function prompt_choice() {
  if [ -z "${1}" ]; then
    echo "Error! You need to pass in a parameter!"
    echo "  ${0} 'Do you like apples?' ('Yes' 'No')"
    exit 1
  fi;
  local -n CHOICE=${1}
  local MSG=${2}
  shift 2;
  local OPTIONS=("$@")


  local MIN=1
  local MAX=${#OPTIONS[@]}
  local OPT=-1
  CHOICE="!@#$%^&*()"

  if [[ ${MAX} -gt 1 ]]; then
    while [[ "${OPT}" -lt ${MIN} || "${OPT}" -gt ${MAX} ]]; do
      for i in "${!OPTIONS[@]}"; do
        echo "$(($i+1))   ${OPTIONS[$i]}"
      done
      read -p "${MSG} " OPT
      if [[ "${OPT}" -ge ${MIN} && "${OPT}" -le ${MAX} ]]; then
        CHOICE="${OPTIONS[$((${OPT}-1))]}"
      fi
    done;
  else
    CHOICE="${OPTIONS[0]}"
  fi;
}
function zssl_download_cert(){
  local CERTID=${1}
  local -n __RET=${2}
  local URI="${ZSSLBASE}/certificates/${CERTID}/download/return?access_key=${ZSSLAPIKEY}"
  __RET=$(curl -s -H "Content-Type: application/json" ${URI})
  
  if [ -z "$(echo ${__RET} | jq -r '."ca_bundle.crt"')" ]; then
    echo "Download of PEM Data failed!"
    echo ${__RET}
    exit 1
  fi
}
function zssl_get_active_certs_by_name() {
  local CERTCN=${1}
  curl -s -H "Content-Type: application/json" ${ZSSLCERTURI}| \
    jq --arg cname "${CERTCN}" --arg issued "${ISSUED}" --arg draft "${DRAFT}" \
      -r '.results | map(select(.common_name == $cname and (.status == $issued or .status == $draft)))'
}
function zssl_request_cert(){
  local CERTCN=${1}
  local -n __RET=${2}
  shift 2;
  local SANS=("$@")
  local DIRSTRUCT="${CERTCN}/$(date '+%Y-%m-%d')"

  # TODO: This is specific to me.
  local PERMADIR="${HOME}/certs/${DIRSTRUCT}"
  local TMPDIR="/tmp/${DIRSTRUCT}"

  if [ ! -d "${PERMADIR}" ]; then
    # echo "  Requesting CSR"
    zssl_request_csr "${TMPDIR}" "${CERTCN}" "${SANS[@]}"
    mkdir -p "${PERMADIR}"
    # If the CSR is valid - we now need to save that CSR somewhere smart!
    mv ${TMPDIR}/* ${PERMADIR}
  fi

  local PRMCSR="${PERMADIR}/${ZSSLCSR}"
  local CSRDATA="$(cat ${PRMCSR} | awk '{printf "%s\n", $0}')" # Replace Newlines with \n for JSON compatibility
  local DOMAIN_LIST="${CERTCN}"
  for DOMAIN in "${SANS[@]}"; do
    DOMAIN_LIST+=",${DOMAIN}"
  done

  # Build the cert detail object
  local NEWCERTDTL=$(jq -c --null-input --arg cert_domains "${DOMAIN_LIST}" --arg csr_data "${CSRDATA}" '{"certificate_domains": $cert_domains, "certificate_csr": $csr_data, "certificate_validity_days": 90, "strict_domains": 1}')

  # Actually make the request
  __RET=$(curl -s -X POST -H "Content-Type: application/json" -d "${NEWCERTDTL}" ${ZSSLCERTURI})
  if [ -z "$(echo ${__RET} | jq -r '.id')" ]; then
    echo "Bad Cert! Do not validate!"
    echo ${__RET}
    exit 1
  fi

  zssl_validate_cert "${__RET}"
}
function zssl_request_csr() {
  # Args
  local TMPDIR=${1}
  local CERTCN=${2}

  #Shift 2 because there are 2 args before this one.
  shift 2;
  local SANS=("$@")

  # Local Constants
  local TMPCSR="${TMPDIR}/${ZSSLCSR}"
  local TMPPK="${TMPDIR}/${ZSSLPRIKEY}"
  local TMPCSRCFG="${TMPDIR}/${ZSSLCSRCFG}"

  #
  rm -rf ${TMPDIR} && mkdir -p ${TMPDIR}

  #
  echo "  Creating CSR for ${CERTCN}!"
  cat > $TMPCSRCFG <<-END
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
END
  # DNS.1 = your-new-domain.com
  for i in "${!SANS[@]}"; do
    echo "DNS.$(($i+1)) = ${SANS[$i]}" >> ${TMPCSRCFG}
  done

  # Generate the CSR and the Private Key
  openssl req -new -sha256 -nodes -out ${TMPCSR} -newkey rsa:2048 -keyout ${TMPPK} -config <( cat $TMPCSRCFG )
  CSRDATA="$(cat ${TMPCSR} | awk '{printf "%s\n", $0}')" # Replace Newlines with \n for JSON compatibility
  CSR=$(jq --null-input --arg csr_data "${CSRDATA}" '{"csr": $csr_data}')

  # Validate CSR!
  VALIDCSR=$(curl -s -X POST -H "Content-Type: application/json" -d "${CSR}" ${ZSSLVERIFYURI})
  if [ "true" != "$(echo ${VALIDCSR} | jq -r '.valid')" ]; then
    echo "Bad CSR! Will not submit!"
    echo ${VALIDCSR}
    exit 1
  fi
}
function zssl_validate_cert(){
  local CERT=${1}
  local CERT_NAME=$(echo ${CERT} | jq -r '.common_name')
  local CERT_ID=$(echo ${CERT} | jq -r '.id')
  local CERT_URI_BASE="${ZSSLBASE}/certificates/${CERT_ID}"
  local CERT_URI="${CERT_URI_BASE}?access_key=${ZSSLAPIKEY}"
  local CERT_CHALLENGEURI="${CERT_URI_BASE}/challenges?access_key=${ZSSLAPIKEY}"
  local RECHECK=0

  #
  if [ "${DRAFT}" == "$(echo ${CERT} | jq -r '.status')" ]; then
    local CID=""
    local KEY=""
    
    #
    echo "  Cert ($CERT_NAME) is in ${DRAFT} state. Validating it!"
    for FQDN in $(echo ${CERT} | jq -r ".validation.other_methods | keys[]"); do
      KEY=$(echo ${CERT} | jq -r ".validation.other_methods.\"${FQDN}\".cname_validation_p1")
      local VAL=$(echo ${CERT} | jq -r ".validation.other_methods.\"${FQDN}\".cname_validation_p2")
      aws_r53_create_if_not_exists ${KEY} ${VAL} CID
    done
    if [ ! -z "${CID}" ]; then
      aws_r53_wait_for_propogation ${KEY} "${CID}"
    fi;

    # # https://zerossl.com/documentation/api/verify-domains/
    local VALIDATE=$(curl -s -X POST -H "Content-Type: application/json" -d '{"validation_method": "CNAME_CSR_HASH"}' ${CERT_CHALLENGEURI})
    local VAL_STATUS=$(echo ${VALIDATE} | jq -r '.status')
    if [ -z "${VAL_STATUS}" ]; then
      echo "Error! Cert is not validating appropriately!"
      echo "${CERT}"
      echo ""
      echo "${VALIDATE}"
      exit 1
    fi

    echo "  Validation Complete! Certificate Status: ${VAL_STATUS}."
    if [ "${PENDING}" == "${VAL_STATUS}" ]; then
      local ISSUE_COUNTER=0
      while [ "${ISSUED}" != "$(echo ${CERT} | jq -r '.status')" ]; do
        echo "  Waiting for ${CERT_NAME} to Issue!. (Waiting: ${ISSUE_COUNTER}, Timeout 2 Minutes)"
        sleep 2;
        CERT=$(curl -s -H "Content-Type: application/json" ${CERT_URI})
        ISSUE_COUNTER=$((ISSUE_COUNTER+1))
        if [ 60 -lt $ISSUE_COUNTER ]; then
          echo "Error - Propagation took too long. (Waiting: ${ISSUE_COUNTER})"
          echo ${CERT}
          exit 99
        fi
      done;
    fi
  fi

  #
  echo "  Cert ($CERT_NAME) successfully issued! Removing DNS Entries!"
  for FQDN in $(echo ${CERT} | jq -r ".validation.other_methods | keys[]"); do
    KEY=$(echo ${CERT} | jq -r ".validation.other_methods.\"${FQDN}\".cname_validation_p1")
    VAL=$(echo ${CERT} | jq -r ".validation.other_methods.\"${FQDN}\".cname_validation_p2")
    aws_r53_delete_if_exists ${KEY} ${VAL}
  done

}

##############################################
##              END FUNCTIONS               ##
##############################################

##############################################
##              MAIN FUNCTION               ##
##############################################

function main() {
  echo "Step 1) Log into Anypoint"
  TOKEN=$(anypoint_login)

  echo "Step 2) Choose a TLS Context to update"
  anypoint_get_tls_contexts ANYCONTEXT

  local EXPIRATION=$(date +%s -d $(echo ${ANYCONTEXT} | jq -r '.keyStore.expirationDate'))

  if $(is_expiring_soon ${EXPIRATION}); then # Function is weird. Just roll with it.
    echo "Step 3) Cert Expires within threshold - start renewal"
    local ANYCONTEXT_CN="$(echo ${ANYCONTEXT} | jq -r '.keyStore.cn')"
    local ZSSLCERTS=$(zssl_get_active_certs_by_name "${ANYCONTEXT_CN}")
    local CERTCOUNT=$(echo ${ZSSLCERTS} | jq -r ". | length")

    # Grab the last cert that expired. We can always revoke the old one later.
    local ZCERT=$(echo "${ZSSLCERTS}" | jq -r " . | sort_by(.expires)[-1]")
    local ZCERT_ID=$(echo ${ZCERT} | jq -r ".id")
    local ZCERT_STATUS=$(echo ${ZCERT} | jq -r '.status')
    local ZCERT_EXP=$(date +%s -d "$(echo ${ZCERT} | jq -r '.expires')")
    local ZCERT_NAME=$(echo ${ZCERT} | jq -r '.common_name')


    echo "  There are ${CERTCOUNT} cert(s) for ${ZCERT_NAME}"
    # At this point there are a couple options of what's happening here:
    # a) If there is a single cert in issued state - we are replacing it.
    # b) If there are 2 certs we are replacing one older one with a newer one
    #     * If there is 1 issued and 1 in draft - then we need to validate it.
    #     * If there are 2 issued - then the new is is validated.
    if [[ 2 -eq ${CERTCOUNT} ]]; then
      zssl_validate_cert "${ZCERT}"
      anypoint_update_context "${ANYCONTEXT}" "${ZCERT}"
    elif [[ 1 == ${CERTCOUNT} ]] && $(is_expiring_soon ${ZCERT_EXP}); then # Function is weird. Just roll with it.
      #
      echo "Step 4) Request a new cert"
      # Convert SAN list into a bash array for use in bash function.
      # Don't make it JSON because you're lazy.
      SAN_LIST=$(echo ${ANYCONTEXT} | jq -r '.keyStore.san')
      SAN_ARR=($(echo ${SAN_LIST} | sed -e 's/\[ //g' -e 's/\ ]//g' -e 's/\,//g' -e 's/"//g'))

      #
      zssl_request_cert "${ANYCONTEXT_CN}" NEW_CERT "${SAN_ARR[@]}"

      echo "Step 5) Update ${ANYCONTEXT_CN} with the new cert ($(echo ${NEW_CERT} | jq -r '.common_name'))"
      anypoint_update_context "${ANYCONTEXT}" "${NEW_CERT}"

      echo "Job Complete! ${ANYCONTEXT_CN} has been updated and expires on $(echo ${NEW_CERT} | jq -r '.expires')"
    fi
  fi
}

# echo "Validating existing cert exists"
# This will download the cert. Doesn't look like we need to.
# </dev/null openssl s_client -connect ${CERTCN}:443 -servername ${CERTCN} | openssl x509 > ${TMPCERTPATH}

main
