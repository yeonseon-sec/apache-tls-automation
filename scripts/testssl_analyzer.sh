#!/bin/bash

# =============================================================
# testssl_analyzer.sh
# testssl.sh의 JSON 진단 결과를 분석하여 취약 항목을 CSV로 저장
# =============================================================

# 입력 파일(JSON)과 출력 파일(CSV) 경로 지정
json_file="result.json"
output_csv="Risk_Report.csv"

# CSV 헤더 초기화
echo "Risk Category,Details,CVE,CWE,Severity" > "$output_csv"

# 서명 알고리즘 분류 기준
critical_signatures=("SHA1" "MD5" "SHA" "DSA" "DH")                   # 취약하거나 비권장된 서명 알고리즘
safe_signatures=("RSA-PSS" "ECDSA" "SHA256" "SHA384" "Ed25519")		  # 안전한 서명 알고리즘
safe_ciphers=("TLS_AES_256_GCM_SHA384" "TLS_AES_128_GCM_SHA256" "TLS_CHACHA20_POLY1305_SHA256" "ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" "ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" "ECDHE_RSA_WITH_AES_256_GCM_SHA384" "ECDHE_RSA_WITH_AES_128_GCM_SHA256" "ECDHE_RSA_WITH_CHACHA20-POLY1305" "ECDHE_ECDSA_WITH_CHACHA20-POLY1305")    # 안전한 암호 스위트 목록

# jq로 JSON 배열을 한 줄씩 읽어 항목별로 분석
jq -c '.[]' "$json_file" | while read -r entry; do
    id=$(echo "$entry" | jq -r '.id // empty')
    cve=$(echo "$entry" | jq -r '.cve // empty')
    cwe=$(echo "$entry" | jq -r '.cwe // empty')
    finding=$(echo "$entry" | jq -r '.finding // empty')
    severity=$(echo "$entry" | jq -r '.severity // empty')

    # 1. 프로토콜 점검
	
	# TLS 1.2, 1.3이 지원되지 않거나 QUIC, ALPN, NPN이 미제공인 경우 취약으로 분류
    if [[ "$id" == "TLS1_2" || "$id" == "TLS1_3" || "$id" == "QUIC" || "$id" == "ALPN" || "$id" == "NPN" ]]; then
	    if [[ "$finding" == *"not offered"* ]]; then
	        echo "protocol,\"$id: $finding\",,," >> "$output_csv"
	    fi
    fi

	# SSLv2, SSLv3, TLS 1.0, TLS 1.1이 활성화된 경우 취약으로 분류
    if [[ "$id" == "TLS1" || "$id" == "TLS1_1" || "$id" == "SSv2" || "$id" == "SSv3" ]]; then
	    if [[ "$finding" != *"not offered"* ]]; then
	        echo "protocol,\"$id: $finding\",,," >> "$output_csv"
	    fi
    fi


	# ALPN이 HTTP/2, HTTP/3를 지원하지 않는 경우 취약으로 분류
    if [[ "$id" == "ALPN" ]]; then
    	case "$finding" in
            *h2*|*h3*|*http/2*|*http/3*) ;;		# 지원하면 정상, 아무것도 하지 않음
            *) echo "protocol,\"$id: $finding\",,,," >> "$output_csv" ;;
    	esac
    fi

    # 2. 암호 스위트 점검
	
	# Forward Secrecy(FS) 미지원 암호 스위트가 사용된 경우 취약으로 분류
    if [[ "$id" == cipherlist* && "$id" == *FS* && "$finding" == *"not offered"* ]]; then
    	echo "cipher,\"$id: $finding\",,,$severity" >> "$output_csv"
    fi

	# FS 외 취약한 암호 스위트 카테고리가 제공되는 경우 취약으로 분류
    if [[ "$id" == cipherlist_* && "$id" != *cipherlist_FS* && "$finding" != *"not offered"* ]]; then
        echo "cipher,\"$id: $finding\",,$cwe,$severity" >> "$output_csv"
    fi

    # 3. 서버 암호 우선순위 점검
	
	# 서버가 사용 중인 암호 스위트가 안전한 목록에 없으면 취약으로 분류
    if [[ "$id" == cipher-* ]]; then
        safe=false
        for cipher in "${safe_ciphers[@]}"; do
            if [[ "$finding" == *"$cipher"* ]]; then
                safe=true
                break
            fi
        done
        if [[ "$safe" == false ]]; then
            echo "cipher_suite,\"$finding\",,," >> "$output_csv"
        fi
    fi

	# 서버 암호 우선순위가 설정되지 않은 경우 취약으로 분류
    if [[ "$id" == cipher_order-* && "$finding" == *"NOT a cipher order configured"* ]]; then
        echo "cipher_suite,\"$id: cipher order not set\",,," >> "$output_csv"
    fi

    # 4. 서명 알고리즘 점검
	
	# 서명 알고리즘이 안전한 목록에 없으면 비권장 서명으로 분류
    if [[ "$id" == *signatureAlgorithm* ]]; then
	    is_safe=false
        for sig in "${safe_signatures[@]}"; do
            if [[ "$finding" == *"$sig"* ]]; then
                is_safe=true
		        break
            fi
        done

	    if [[ "$is_safe" == false ]]; then
  	        echo "signature_algorithm,\"Non-recommended signature: $finding\",,," >> "$output_csv"
	    fi
		
		# 취약한 서명 알고리즘이 단독으로 사용된 경우 위험으로 분류
	    is_weak=false
        for weak in "${critical_signatures[@]}"; do
            if [[ "$finding" == "$weak" ]]; then
	            is_weak=true
		        break
            fi
        done

        if [[ "$is_weak" == true ]]; then
	        echo "signature_algorithm,\"Very weak signature: $finding\",,," >> "$output_csv"
        fi 
    fi
	    
    # 5. 인증서 키 길이 점검
	
	# RSA 2048bit 미만, ECDSA 224bit 미만인 경우 취약으로 분류
    if [[ "$id" == *keySize* ]]; then
        read -ra parts <<< "$finding"
        if [[ ${#parts[@]} -ge 2 ]]; then
            if (( parts[1] > 0 || parts[1] == 0 )); then
                algo="${parts[0]}"
                key_size="${parts[1]}"
                if [[ "$algo" == "RSA" && "$key_size" -lt 2048 ]]; then
                    echo "cert_keysize,\"$finding\",,," >> "$output_csv"
                fi
                if [[ "$algo" == "ECDSA" && "$key_size" -lt 224 ]]; then
                    echo "cert_keysize,\"$finding\",,," >> "$output_csv"
                fi
            fi
        fi
    fi

    # 6. 인증서 신뢰 정보 점검
	
	# SAN, 신뢰 체인, DNS, OCSP 관련 항목 중 심각도가 있는 경우 취약으로 분류
    if [[ "$id" == *subjectAltName* || "$id" == *trust* || "$id" == *DNS* || "$finding" == *OCSP* ]]; then
        for sev in "${severities[@]}"; do
            if [[ "$severity" == "$sev" ]]; then
                echo "certification,\"$id: $finding\",,,$severity" >> "$output_csv"
                break
            fi
        done
    fi

	# OCSP Stapling이 미지원인 경우 취약으로 분류
    if [[ "$id" == *"OCSP stapling"* && "$finding" == *"not offered"* ]]; then
        echo "certification,\"$id: $finding\",,," >> "$output_csv"
    fi

    # 7. HTTP 헤더 점검
	
	# HSTS 헤더가 적용되지 않은 경우 취약으로 분류
    if [[ "$id" == *HSTS* && "$finding" == *"not offered"* ]]; then
        echo "HTTP_header,\"$id\",,,$severity" >> "$output_csv"
    fi

	# HPKP(공개키 고정)가 미지원인 경우 취약으로 분류
    if [[ "$id" == *HPKP* && "$finding" == *"No support"* ]]; then
        echo "HTTP_header,\"$id: $finding\",,," >> "$output_csv"
    fi

	# 서버 배너에 Apache 또는 nginx 버전 정보가 노출된 경우 취약으로 분류
    if [[ "$id" == *banner* ]]; then
        if [[ "$finding" == *"Apache"* || "$finding" == *"nginx"* ]]; then
            echo "HTTP_header,\"server version: $finding\",,," >> "$output_csv"
        fi
    fi

	# 기타 HTTP 보안 헤더 항목 중 심각도가 있는 경우 취약으로 분류
    if [[ "$id" == *headers* ]]; then
        for sev in "${severities[@]}"; do
            if [[ "$severity" == "$sev" ]]; then
                echo "HTTP_header,\"$id\",,,$severity" >> "$output_csv"
                break
            fi
        done
    fi

    # 8. CVE 취약점 점검
	
	# CVE가 존재하고 심각도가 OK가 아닌 경우 취약으로 분류
    if [[ "$cve" == *CVE* && "$severity" != *OK* ]]; then
        echo "vulnerabilities,\"$id: $finding\",$cve,$cwe,$severity" >> "$output_csv"
    fi

    # 9. 종합 등급 점검

	# testssl.sh 종합 등급 항목에 CVS에 기록
    if [[ "$id" == *grade* ]]; then
        echo "overall_grade,\"$id: $finding\",,,$severity" >> "$output_csv"
    fi
done

echo "Analysis completed. Result: $output_csv"
