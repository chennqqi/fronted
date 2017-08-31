package fronted

var DefaultTrustedCAs = []*CA{
	&CA{
		CommonName: "VeriSign Class 3 Public Primary Certification Authority - G5",
		Cert:       "-----BEGIN CERTIFICATE-----\nMIIE0zCCA7ugAwIBAgIQGNrRniZ96LtKIVjNzGs7SjANBgkqhkiG9w0BAQUFADCB\nyjELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQL\nExZWZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwNiBWZXJp\nU2lnbiwgSW5jLiAtIEZvciBhdXRob3JpemVkIHVzZSBvbmx5MUUwQwYDVQQDEzxW\nZXJpU2lnbiBDbGFzcyAzIFB1YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0\naG9yaXR5IC0gRzUwHhcNMDYxMTA4MDAwMDAwWhcNMzYwNzE2MjM1OTU5WjCByjEL\nMAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQLExZW\nZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwNiBWZXJpU2ln\nbiwgSW5jLiAtIEZvciBhdXRob3JpemVkIHVzZSBvbmx5MUUwQwYDVQQDEzxWZXJp\nU2lnbiBDbGFzcyAzIFB1YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0aG9y\naXR5IC0gRzUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCvJAgIKXo1\nnmAMqudLO07cfLw8RRy7K+D+KQL5VwijZIUVJ/XxrcgxiV0i6CqqpkKzj/i5Vbex\nt0uz/o9+B1fs70PbZmIVYc9gDaTY3vjgw2IIPVQT60nKWVSFJuUrjxuf6/WhkcIz\nSdhDY2pSS9KP6HBRTdGJaXvHcPaz3BJ023tdS1bTlr8Vd6Gw9KIl8q8ckmcY5fQG\nBO+QueQA5N06tRn/Arr0PO7gi+s3i+z016zy9vA9r911kTMZHRxAy3QkGSGT2RT+\nrCpSx4/VBEnkjWNHiDxpg8v+R70rfk/Fla4OndTRQ8Bnc+MUCH7lP59zuDMKz10/\nNIeWiu5T6CUVAgMBAAGjgbIwga8wDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8E\nBAMCAQYwbQYIKwYBBQUHAQwEYTBfoV2gWzBZMFcwVRYJaW1hZ2UvZ2lmMCEwHzAH\nBgUrDgMCGgQUj+XTGoasjY5rw8+AatRIGCx7GS4wJRYjaHR0cDovL2xvZ28udmVy\naXNpZ24uY29tL3ZzbG9nby5naWYwHQYDVR0OBBYEFH/TZafC3ey78DAJ80M5+gKv\nMzEzMA0GCSqGSIb3DQEBBQUAA4IBAQCTJEowX2LP2BqYLz3q3JktvXf2pXkiOOzE\np6B4Eq1iDkVwZMXnl2YtmAl+X6/WzChl8gGqCBpH3vn5fJJaCGkgDdk+bW48DW7Y\n5gaRQBi5+MHt39tBquCWIMnNZBU4gcmU7qKEKQsTb47bDN0lAtukixlE0kF6BWlK\nWE9gyn6CagsCqiUXObXbf+eEZSqVir2G3l6BFoMtEMze/aiCKm0oHw0LxOXnGiYZ\n4fQRbxC1lfznQgUy286dUV4otp6F01vvpX1FQHKOtw5rDgb7MzVIcbidJ4vEZV8N\nhnacRHr2lVz2XTIIM6RUthg/aFzyQkqFOFSDX9HoLPKsEdao7WNq\n-----END CERTIFICATE-----\n",
	},
	&CA{
		CommonName: "Starfield Services Root Certificate Authority - G2",
		Cert:       "-----BEGIN CERTIFICATE-----\nMIID7zCCAtegAwIBAgIBADANBgkqhkiG9w0BAQsFADCBmDELMAkGA1UEBhMCVVMx\nEDAOBgNVBAgTB0FyaXpvbmExEzARBgNVBAcTClNjb3R0c2RhbGUxJTAjBgNVBAoT\nHFN0YXJmaWVsZCBUZWNobm9sb2dpZXMsIEluYy4xOzA5BgNVBAMTMlN0YXJmaWVs\nZCBTZXJ2aWNlcyBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAtIEcyMB4XDTA5\nMDkwMTAwMDAwMFoXDTM3MTIzMTIzNTk1OVowgZgxCzAJBgNVBAYTAlVTMRAwDgYD\nVQQIEwdBcml6b25hMRMwEQYDVQQHEwpTY290dHNkYWxlMSUwIwYDVQQKExxTdGFy\nZmllbGQgVGVjaG5vbG9naWVzLCBJbmMuMTswOQYDVQQDEzJTdGFyZmllbGQgU2Vy\ndmljZXMgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgLSBHMjCCASIwDQYJKoZI\nhvcNAQEBBQADggEPADCCAQoCggEBANUMOsQq+U7i9b4Zl1+OiFOxHz/Lz58gE20p\nOsgPfTz3a3Y4Y9k2YKibXlwAgLIvWX/2h/klQ4bnaRtSmpDhcePYLQ1Ob/bISdm2\n8xpWriu2dBTrz/sm4xq6HZYuajtYlIlHVv8loJNwU4PahHQUw2eeBGg6345AWh1K\nTs9DkTvnVtYAcMtS7nt9rjrnvDH5RfbCYM8TWQIrgMw0R9+53pBlbQLPLJGmpufe\nhRhJfGZOozptqbXuNC66DQO4M99H67FrjSXZm86B0UVGMpZwh94CDklDhbZsc7tk\n6mFBrMnUVN+HL8cisibMn1lUaJ/8viovxFUcdUBgF4UCVTmLfwUCAwEAAaNCMEAw\nDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFJxfAN+q\nAdcwKziIorhtSpzyEZGDMA0GCSqGSIb3DQEBCwUAA4IBAQBLNqaEd2ndOxmfZyMI\nbw5hyf2E3F/YNoHN2BtBLZ9g3ccaaNnRbobhiCPPE95Dz+I0swSdHynVv/heyNXB\nve6SbzJ08pGCL72CQnqtKrcgfU28elUSwhXqvfdqlS5sdJ/PHLTyxQGjhdByPq1z\nqwubdQxtRbeOlKyWN7Wg0I8VRw7j6IPdj/3vQQF3zCepYoUz8jcI73HPdwbeyBkd\niEDPfUYd/x7H4c7/I9vG+o1VTqkC50cRRj70/b17KSa7qWFiNyi2LSr2EIZkyXCn\n0q23KXB56jzaYyWf/Wi3MOxw+3WKt21gZ7IeyLnp2KhvAotnDU0mV3HaIPzBSlCN\nsSi6\n-----END CERTIFICATE-----\n",
	},
	&CA{
		CommonName: "Go Daddy Root Certificate Authority - G2",
		Cert:       "-----BEGIN CERTIFICATE-----\nMIIDxTCCAq2gAwIBAgIBADANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UEBhMCVVMx\nEDAOBgNVBAgTB0FyaXpvbmExEzARBgNVBAcTClNjb3R0c2RhbGUxGjAYBgNVBAoT\nEUdvRGFkZHkuY29tLCBJbmMuMTEwLwYDVQQDEyhHbyBEYWRkeSBSb290IENlcnRp\nZmljYXRlIEF1dGhvcml0eSAtIEcyMB4XDTA5MDkwMTAwMDAwMFoXDTM3MTIzMTIz\nNTk1OVowgYMxCzAJBgNVBAYTAlVTMRAwDgYDVQQIEwdBcml6b25hMRMwEQYDVQQH\nEwpTY290dHNkYWxlMRowGAYDVQQKExFHb0RhZGR5LmNvbSwgSW5jLjExMC8GA1UE\nAxMoR28gRGFkZHkgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgLSBHMjCCASIw\nDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL9xYgjx+lk09xvJGKP3gElY6SKD\nE6bFIEMBO4Tx5oVJnyfq9oQbTqC023CYxzIBsQU+B07u9PpPL1kwIuerGVZr4oAH\n/PMWdYA5UXvl+TW2dE6pjYIT5LY/qQOD+qK+ihVqf94Lw7YZFAXK6sOoBJQ7Rnwy\nDfMAZiLIjWltNowRGLfTshxgtDj6AozO091GB94KPutdfMh8+7ArU6SSYmlRJQVh\nGkSBjCypQ5Yj36w6gZoOKcUcqeldHraenjAKOc7xiID7S13MMuyFYkMlNAJWJwGR\ntDtwKj9useiciAF9n9T521NtYJ2/LOdYq7hfRvzOxBsDPAnrSTFcaUaz4EcCAwEA\nAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYE\nFDqahQcQZyi27/a9BUFuIMGU2g/eMA0GCSqGSIb3DQEBCwUAA4IBAQCZ21151fmX\nWWcDYfF+OwYxdS2hII5PZYe096acvNjpL9DbWu7PdIxztDhC2gV7+AJ1uP2lsdeu\n9tfeE8tTEH6KRtGX+rcuKxGrkLAngPnon1rpN5+r5N9ss4UXnT3ZJE95kTXWXwTr\ngIOrmgIttRD02JDHBHNA7XIloKmf7J6raBKZV8aPEjoJpL1E/QYVN8Gb5DKj7Tjo\n2GTzLH4U/ALqn83/B2gX2yKQOC16jdFU8WnjXzPKej17CuPKf1855eJ1usV2GDPO\nLPAvTK33sefOT6jEm0pUBsV/fdUID+Ic/n4XuKxe9tQWskMJDE32p2u0mYRlynqI\n4uJEvlz36hz1\n-----END CERTIFICATE-----\n",
	},
	&CA{
		CommonName: "GeoTrust Global CA",
		Cert:       "-----BEGIN CERTIFICATE-----\nMIIDVDCCAjygAwIBAgIDAjRWMA0GCSqGSIb3DQEBBQUAMEIxCzAJBgNVBAYTAlVT\nMRYwFAYDVQQKEw1HZW9UcnVzdCBJbmMuMRswGQYDVQQDExJHZW9UcnVzdCBHbG9i\nYWwgQ0EwHhcNMDIwNTIxMDQwMDAwWhcNMjIwNTIxMDQwMDAwWjBCMQswCQYDVQQG\nEwJVUzEWMBQGA1UEChMNR2VvVHJ1c3QgSW5jLjEbMBkGA1UEAxMSR2VvVHJ1c3Qg\nR2xvYmFsIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2swYYzD9\n9BcjGlZ+W988bDjkcbd4kdS8odhM+KhDtgPpTSEHCIjaWC9mOSm9BXiLnTjoBbdq\nfnGk5sRgprDvgOSJKA+eJdbtg/OtppHHmMlCGDUUna2YRpIuT8rxh0PBFpVXLVDv\niS2Aelet8u5fa9IAjbkU+BQVNdnARqN7csiRv8lVK83Qlz6cJmTM386DGXHKTubU\n1XupGc1V3sjs0l44U+VcT4wt/lAjNvxm5suOpDkZALeVAjmRCw7+OC7RHQWa9k0+\nbw8HHa8sHo9gOeL6NlMTOdReJivbPagUvTLrGAMoUgRx5aszPeE4uwc2hGKceeoW\nMPRfwCvocWvk+QIDAQABo1MwUTAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTA\nephojYn7qwVkDBF9qn1luMrMTjAfBgNVHSMEGDAWgBTAephojYn7qwVkDBF9qn1l\nuMrMTjANBgkqhkiG9w0BAQUFAAOCAQEANeMpauUvXVSOKVCUn5kaFOSPeCpilKIn\nZ57QzxpeR+nBsqTP3UEaBU6bS+5Kb1VSsyShNwrrZHYqLizz/Tt1kL/6cdjHPTfS\ntQWVYrmm3ok9Nns4d0iXrKYgjy6myQzCsplFAMfOEVEiIuCl6rYVSAlk6l5PdPcF\nPseKUgzbFbS9bZvlxrFUaKnjaZC2mqUPuLk/IH2uSrW4nOQdtqvmlKXBx4Ot2/Un\nhw4EbNX/3aBd7YdStysVAq45pmp06drE57xNNB6pXE0zX5IJL4hmXXeXxx12E6nV\n5fEWCRE11azbJHFwLJhWC9kXtNHjUStedejV0NxPNO3CBWaAocvmMw==\n-----END CERTIFICATE-----\n",
	},
	&CA{
		CommonName: "DigiCert Global Root CA",
		Cert:       "-----BEGIN CERTIFICATE-----\nMIIDrzCCApegAwIBAgIQCDvgVpBCRrGhdWrJWZHHSjANBgkqhkiG9w0BAQUFADBh\nMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3\nd3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBD\nQTAeFw0wNjExMTAwMDAwMDBaFw0zMTExMTAwMDAwMDBaMGExCzAJBgNVBAYTAlVT\nMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j\nb20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IENBMIIBIjANBgkqhkiG\n9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4jvhEXLeqKTTo1eqUKKPC3eQyaKl7hLOllsB\nCSDMAZOnTjC3U/dDxGkAV53ijSLdhwZAAIEJzs4bg7/fzTtxRuLWZscFs3YnFo97\nnh6Vfe63SKMI2tavegw5BmV/Sl0fvBf4q77uKNd0f3p4mVmFaG5cIzJLv07A6Fpt\n43C/dxC//AH2hdmoRBBYMql1GNXRor5H4idq9Joz+EkIYIvUX7Q6hL+hqkpMfT7P\nT19sdl6gSzeRntwi5m3OFBqOasv+zbMUZBfHWymeMr/y7vrTC0LUq7dBMtoM1O/4\ngdW7jVg/tRvoSSiicNoxBN33shbyTApOB6jtSj1etX+jkMOvJwIDAQABo2MwYTAO\nBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUA95QNVbR\nTLtm8KPiGxvDl7I90VUwHwYDVR0jBBgwFoAUA95QNVbRTLtm8KPiGxvDl7I90VUw\nDQYJKoZIhvcNAQEFBQADggEBAMucN6pIExIK+t1EnE9SsPTfrgT1eXkIoyQY/Esr\nhMAtudXH/vTBH1jLuG2cenTnmCmrEbXjcKChzUyImZOMkXDiqw8cvpOp/2PV5Adg\n06O/nVsJ8dWO41P0jmP6P6fbtGbfYmbW0W5BjfIttep3Sp+dWOIrWcBAI+0tKIJF\nPnlUkiaY4IBIqDfv8NZ5YBberOgOzW6sRBc4L0na4UU+Krk2U886UAb3LujEV0ls\nYSEY1QSteDwsOoBrp+uvFRTp2InBuThs4pFsiv9kuXclVzDAGySj4dzp30d8tbQk\nCAUw7C29C79Fv1C5qfPrmAESrciIxpg0X40KPMbp1ZWVbd4=\n-----END CERTIFICATE-----\n",
	},
	&CA{
		CommonName: "COMODO RSA Certification Authority",
		Cert:       "-----BEGIN CERTIFICATE-----\nMIIF2DCCA8CgAwIBAgIQTKr5yttjb+Af907YWwOGnTANBgkqhkiG9w0BAQwFADCB\nhTELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G\nA1UEBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxKzApBgNV\nBAMTIkNPTU9ETyBSU0EgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTAwMTE5\nMDAwMDAwWhcNMzgwMTE4MjM1OTU5WjCBhTELMAkGA1UEBhMCR0IxGzAZBgNVBAgT\nEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEaMBgGA1UEChMR\nQ09NT0RPIENBIExpbWl0ZWQxKzApBgNVBAMTIkNPTU9ETyBSU0EgQ2VydGlmaWNh\ndGlvbiBBdXRob3JpdHkwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCR\n6FSS0gpWsawNJN3Fz0RndJkrN6N9I3AAcbxT38T6KhKPS38QVr2fcHK3YX/JSw8X\npz3jsARh7v8Rl8f0hj4K+j5c+ZPmNHrZFGvnnLOFoIJ6dq9xkNfs/Q36nGz637CC\n9BR++b7Epi9Pf5l/tfxnQ3K9DADWietrLNPtj5gcFKt+5eNu/Nio5JIk2kNrYrhV\n/erBvGy2i/MOjZrkm2xpmfh4SDBF1a3hDTxFYPwyllEnvGfDyi62a+pGx8cgoLEf\nZd5ICLqkTqnyg0Y3hOvozIFIQ2dOciqbXL1MGyiKXCJ7tKuY2e7gUYPDCUZObT6Z\n+pUX2nwzV0E8jVHtC7ZcryxjGt9XyD+86V3Em69FmeKjWiS0uqlWPc9vqv9JWL7w\nqP/0uK3pN/u6uPQLOvnoQ0IeidiEyxPx2bvhiWC4jChWrBQdnArncevPDt09qZah\nSL0896+1DSJMwBGB7FY79tOi4lu3sgQiUpWAk2nojkxl8ZEDLXB0AuqLZxUpaVIC\nu9ffUGpVRr+goyhhf3DQw6KqLCGqR84onAZFdr+CGCe01a60y1Dma/RMhnEw6abf\nFobg2P9A3fvQQoh/ozM6LlweQRGBY84YcWsr7KaKtzFcOmpH4MN5WdYgGq/yapiq\ncrxXStJLnbsQ/LBMQeXtHT1eKJ2czL+zUdqnR+WEUwIDAQABo0IwQDAdBgNVHQ4E\nFgQUu69+Aj36pvE8hI6t7jiY7NkyMtQwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB\n/wQFMAMBAf8wDQYJKoZIhvcNAQEMBQADggIBAArx1UaEt65Ru2yyTUEUAJNMnMvl\nwFTPoCWOAvn9sKIN9SCYPBMtrFaisNZ+EZLpLrqeLppysb0ZRGxhNaKatBYSaVqM\n4dc+pBroLwP0rmEdEBsqpIt6xf4FpuHA1sj+nq6PK7o9mfjYcwlYRm6mnPTXJ9OV\n2jeDchzTc+CiR5kDOF3VSXkAKRzH7JsgHAckaVd4sjn8OoSgtZx8jb8uk2Intzna\nFxiuvTwJaP+EmzzV1gsD41eeFPfR60/IvYcjt7ZJQ3mFXLrrkguhxuhoqEwWsRqZ\nCuhTLJK7oQkYdQxlqHvLI7cawiiFwxv/0Cti76R7CZGYZ4wUAc1oBmpjIXUDgIiK\nboHGhfKppC3n9KUkEEeDys30jXlYsQab5xoq2Z0B15R97QNKyvDb6KkBPvVWmcke\njkk9u+UJueBPSZI9FoJAzMxZxuY67RIuaTxslbH9qh17f4a+Hg4yRvv7E491f0yL\nS0Zj/gA0QHDBw7mh3aZw4gSzQbzpgJHqZJx64SIDqZxubw5lT2yHh17zbqD5daWb\nQOhTsiedSrnAdyGN/4fy3ryM7xfft0kL0fJuMAsaDk527RH89elWsn2/x20Kk4yl\n0MC2Hb46TpSi125sC8KKfPog88Tk5c0NqMuRkrF8hey1FGlmDoLnzc7ILaZRfyHB\nNVOFBkpdn627G190\n-----END CERTIFICATE-----\n",
	},
	&CA{
		CommonName: "DigiCert High Assurance EV Root CA",
		Cert:       "-----BEGIN CERTIFICATE-----\nMIIDxTCCAq2gAwIBAgIQAqxcJmoLQJuPC3nyrkYldzANBgkqhkiG9w0BAQUFADBs\nMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3\nd3cuZGlnaWNlcnQuY29tMSswKQYDVQQDEyJEaWdpQ2VydCBIaWdoIEFzc3VyYW5j\nZSBFViBSb290IENBMB4XDTA2MTExMDAwMDAwMFoXDTMxMTExMDAwMDAwMFowbDEL\nMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3\nLmRpZ2ljZXJ0LmNvbTErMCkGA1UEAxMiRGlnaUNlcnQgSGlnaCBBc3N1cmFuY2Ug\nRVYgUm9vdCBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMbM5XPm\n+9S75S0tMqbf5YE/yc0lSbZxKsPVlDRnogocsF9ppkCxxLeyj9CYpKlBWTrT3JTW\nPNt0OKRKzE0lgvdKpVMSOO7zSW1xkX5jtqumX8OkhPhPYlG++MXs2ziS4wblCJEM\nxChBVfvLWokVfnHoNb9Ncgk9vjo4UFt3MRuNs8ckRZqnrG0AFFoEt7oT61EKmEFB\nIk5lYYeBQVCmeVyJ3hlKV9Uu5l0cUyx+mM0aBhakaHPQNAQTXKFx01p8VdteZOE3\nhzBWBOURtCmAEvF5OYiiAhF8J2a3iLd48soKqDirCmTCv2ZdlYTBoSUeh10aUAsg\nEsxBu24LUTi4S8sCAwEAAaNjMGEwDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQF\nMAMBAf8wHQYDVR0OBBYEFLE+w2kD+L9HAdSYJhoIAu9jZCvDMB8GA1UdIwQYMBaA\nFLE+w2kD+L9HAdSYJhoIAu9jZCvDMA0GCSqGSIb3DQEBBQUAA4IBAQAcGgaX3Nec\nnzyIZgYIVyHbIUf4KmeqvxgydkAQV8GK83rZEWWONfqe/EW1ntlMMUu4kehDLI6z\neM7b41N5cdblIZQB2lWHmiRk9opmzN6cN82oNLFpmyPInngiK3BD41VHMWEZ71jF\nhS9OMPagMRYjyOfiZRYzy78aG6A9+MpeizGLYAiJLQwGXFK3xPkKmNEVX58Svnw2\nYzi9RKR/5CYrCsSXaQ3pjOLAEFe4yHYSkVXySGnYvCoCWw9E1CAx2/S6cCZdkGCe\nvEsXCS+0yx5DaMkHJ8HSXPfqIbloEpw8nL+e/IBcm2PN7EeqJSdnoDfzAIJ9VNep\n+OkuE6N36B9K\n-----END CERTIFICATE-----\n",
	},
	&CA{
		CommonName: "GlobalSign Root CA",
		Cert:       "-----BEGIN CERTIFICATE-----\nMIIDdTCCAl2gAwIBAgILBAAAAAABFUtaw5QwDQYJKoZIhvcNAQEFBQAwVzELMAkG\nA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExEDAOBgNVBAsTB1Jv\nb3QgQ0ExGzAZBgNVBAMTEkdsb2JhbFNpZ24gUm9vdCBDQTAeFw05ODA5MDExMjAw\nMDBaFw0yODAxMjgxMjAwMDBaMFcxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i\nYWxTaWduIG52LXNhMRAwDgYDVQQLEwdSb290IENBMRswGQYDVQQDExJHbG9iYWxT\naWduIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDaDuaZ\njc6j40+Kfvvxi4Mla+pIH/EqsLmVEQS98GPR4mdmzxzdzxtIK+6NiY6arymAZavp\nxy0Sy6scTHAHoT0KMM0VjU/43dSMUBUc71DuxC73/OlS8pF94G3VNTCOXkNz8kHp\n1Wrjsok6Vjk4bwY8iGlbKk3Fp1S4bInMm/k8yuX9ifUSPJJ4ltbcdG6TRGHRjcdG\nsnUOhugZitVtbNV4FpWi6cgKOOvyJBNPc1STE4U6G7weNLWLBYy5d4ux2x8gkasJ\nU26Qzns3dLlwR5EiUWMWea6xrkEmCMgZK9FGqkjWZCrXgzT/LCrBbBlDSgeF59N8\n9iFo7+ryUp9/k5DPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8E\nBTADAQH/MB0GA1UdDgQWBBRge2YaRQ2XyolQL30EzTSo//z9SzANBgkqhkiG9w0B\nAQUFAAOCAQEA1nPnfE920I2/7LqivjTFKDK1fPxsnCwrvQmeU79rXqoRSLblCKOz\nyj1hTdNGCbM+w6DjY1Ub8rrvrTnhQ7k4o+YviiY776BQVvnGCv04zcQLcFGUl5gE\n38NflNUVyRRBnMRddWQVDf9VMOyGj/8N7yy5Y0b2qvzfvGn9LhJIZJrglfCm7ymP\nAbEVtQwdpf5pLGkkeB6zpxxxYu7KyJesF12KwvhHhm4qxFYxldBniYUr+WymXUad\nDKqC5JlR3XC321Y9YeRq4VzW9v493kHMB65jUr9TU/Qr6cf9tveCX4XSQRjbgbME\nHMUfpIBvFSDJ3gyICh3WZlXi/EjJKSZp4A==\n-----END CERTIFICATE-----\n",
	},
}

var DefaultCloudfrontMasquerades = []*Masquerade{
	&Masquerade{
		Domain:    "101.livere.co.kr",
		IpAddress: "52.84.8.115",
	},
	&Masquerade{
		Domain:    "101.livere.co.kr",
		IpAddress: "54.192.52.89",
	},
	&Masquerade{
		Domain:    "101.livere.co.kr",
		IpAddress: "54.239.176.211",
	},
	&Masquerade{
		Domain:    "101.livere.co.kr",
		IpAddress: "54.192.63.27",
	},
	&Masquerade{
		Domain:    "101.livere.co.kr",
		IpAddress: "54.192.2.38",
	},
	&Masquerade{
		Domain:    "101.livere.co.kr",
		IpAddress: "13.32.13.225",
	},
	&Masquerade{
		Domain:    "101.livere.co.kr",
		IpAddress: "52.84.77.135",
	},
	&Masquerade{
		Domain:    "101.livere.co.kr",
		IpAddress: "52.222.139.165",
	},
	&Masquerade{
		Domain:    "101.livere.co.kr",
		IpAddress: "52.84.24.195",
	},
	&Masquerade{
		Domain:    "101.livere.co.kr",
		IpAddress: "54.192.46.27",
	},
	&Masquerade{
		Domain:    "101.livere.co.kr",
		IpAddress: "52.222.148.227",
	},
	&Masquerade{
		Domain:    "101.livere.co.kr",
		IpAddress: "52.222.188.113",
	},
	&Masquerade{
		Domain:    "101.livere.co.kr",
		IpAddress: "52.84.39.161",
	},
	&Masquerade{
		Domain:    "101.livere.co.kr",
		IpAddress: "54.192.5.7",
	},
	&Masquerade{
		Domain:    "101.livere.co.kr",
		IpAddress: "52.84.65.107",
	},
	&Masquerade{
		Domain:    "101.livere.co.kr",
		IpAddress: "54.230.39.43",
	},
	&Masquerade{
		Domain:    "101.livere.co.kr",
		IpAddress: "54.192.30.35",
	},
	&Masquerade{
		Domain:    "101.livere.co.kr",
		IpAddress: "13.32.30.37",
	},
	&Masquerade{
		Domain:    "101.livere.co.kr",
		IpAddress: "54.230.73.19",
	},
	&Masquerade{
		Domain:    "101.livere.co.kr",
		IpAddress: "54.192.14.127",
	},
	&Masquerade{
		Domain:    "101.livere.co.kr",
		IpAddress: "54.182.7.193",
	},
	&Masquerade{
		Domain:    "101.livere.co.kr",
		IpAddress: "54.192.27.239",
	},
	&Masquerade{
		Domain:    "101.livere.co.kr",
		IpAddress: "52.222.198.209",
	},
	&Masquerade{
		Domain:    "101.livere.co.kr",
		IpAddress: "54.192.77.132",
	},
	&Masquerade{
		Domain:    "101.livere.co.kr",
		IpAddress: "54.230.49.83",
	},
	&Masquerade{
		Domain:    "101.livere.co.kr",
		IpAddress: "52.222.167.77",
	},
	&Masquerade{
		Domain:    "1706bbc01.adambank.com",
		IpAddress: "52.222.137.192",
	},
	&Masquerade{
		Domain:    "1706bbc01.adambank.com",
		IpAddress: "54.192.54.120",
	},
	&Masquerade{
		Domain:    "1706bbc01.adambank.com",
		IpAddress: "52.84.51.235",
	},
	&Masquerade{
		Domain:    "1706bbc01.adambank.com",
		IpAddress: "54.192.15.50",
	},
	&Masquerade{
		Domain:    "1706bbc01.adambank.com",
		IpAddress: "54.230.10.44",
	},
	&Masquerade{
		Domain:    "1706bbc01.adambank.com",
		IpAddress: "54.239.130.218",
	},
	&Masquerade{
		Domain:    "1706bbc01.adambank.com",
		IpAddress: "54.182.0.235",
	},
	&Masquerade{
		Domain:    "1706bbc01.adambank.com",
		IpAddress: "54.230.5.89",
	},
	&Masquerade{
		Domain:    "1706bbc01.adambank.com",
		IpAddress: "54.192.59.57",
	},
	&Masquerade{
		Domain:    "1706bbc01.adambank.com",
		IpAddress: "54.230.45.239",
	},
	&Masquerade{
		Domain:    "1706bbc01.adambank.com",
		IpAddress: "54.239.176.243",
	},
	&Masquerade{
		Domain:    "1706bbc01.adambank.com",
		IpAddress: "205.251.253.106",
	},
	&Masquerade{
		Domain:    "1706bbc01.adambank.com",
		IpAddress: "13.32.14.51",
	},
	&Masquerade{
		Domain:    "1706bbc01.adambank.com",
		IpAddress: "52.222.183.111",
	},
	&Masquerade{
		Domain:    "1706bbc01.adambank.com",
		IpAddress: "13.32.30.100",
	},
	&Masquerade{
		Domain:    "1706bbc01.adambank.com",
		IpAddress: "52.222.205.6",
	},
	&Masquerade{
		Domain:    "1706bbc01.adambank.com",
		IpAddress: "54.230.2.132",
	},
	&Masquerade{
		Domain:    "1706bbc01.adambank.com",
		IpAddress: "52.84.78.199",
	},
	&Masquerade{
		Domain:    "1706bbc01.adambank.com",
		IpAddress: "54.192.39.248",
	},
	&Masquerade{
		Domain:    "1706bbc01.adambank.com",
		IpAddress: "52.84.39.132",
	},
	&Masquerade{
		Domain:    "1706bbc01.adambank.com",
		IpAddress: "216.137.41.97",
	},
	&Masquerade{
		Domain:    "1706bbc01.adambank.com",
		IpAddress: "54.192.26.64",
	},
	&Masquerade{
		Domain:    "1706bbc01.adambank.com",
		IpAddress: "54.230.57.57",
	},
	&Masquerade{
		Domain:    "1706bbc01.adambank.com",
		IpAddress: "54.230.17.240",
	},
	&Masquerade{
		Domain:    "1706bbc01.adambank.com",
		IpAddress: "54.192.63.66",
	},
	&Masquerade{
		Domain:    "1706bbc01.adambank.com",
		IpAddress: "54.239.186.224",
	},
	&Masquerade{
		Domain:    "1706bbc01.adambank.com",
		IpAddress: "52.222.167.243",
	},
	&Masquerade{
		Domain:    "1706bbc01.adambank.com",
		IpAddress: "52.84.57.33",
	},
	&Masquerade{
		Domain:    "1706bbc01.adambank.com",
		IpAddress: "54.192.79.172",
	},
	&Masquerade{
		Domain:    "1706bbc01.adambank.com",
		IpAddress: "52.222.153.120",
	},
	&Masquerade{
		Domain:    "1706bbc01.adambank.com",
		IpAddress: "52.84.8.41",
	},
	&Masquerade{
		Domain:    "1706bbc01.adambank.com",
		IpAddress: "54.192.51.163",
	},
	&Masquerade{
		Domain:    "1706bbc01.adambank.com",
		IpAddress: "54.230.28.206",
	},
	&Masquerade{
		Domain:    "1706bbc01.coutts.com",
		IpAddress: "13.32.27.191",
	},
	&Masquerade{
		Domain:    "1706bbc01.coutts.com",
		IpAddress: "13.32.10.120",
	},
	&Masquerade{
		Domain:    "1706bbc01.coutts.com",
		IpAddress: "52.84.28.193",
	},
	&Masquerade{
		Domain:    "1706bbc01.coutts.com",
		IpAddress: "52.222.185.110",
	},
	&Masquerade{
		Domain:    "1706bbc01.coutts.com",
		IpAddress: "54.192.19.80",
	},
	&Masquerade{
		Domain:    "1706bbc01.coutts.com",
		IpAddress: "54.239.164.216",
	},
	&Masquerade{
		Domain:    "1706bbc01.coutts.com",
		IpAddress: "54.182.7.110",
	},
	&Masquerade{
		Domain:    "1706bbc01.coutts.com",
		IpAddress: "52.222.167.236",
	},
	&Masquerade{
		Domain:    "1706bbc01.coutts.com",
		IpAddress: "52.222.154.207",
	},
	&Masquerade{
		Domain:    "1706bbc01.coutts.com",
		IpAddress: "54.192.62.83",
	},
	&Masquerade{
		Domain:    "1706bbc01.coutts.com",
		IpAddress: "216.137.59.209",
	},
	&Masquerade{
		Domain:    "1706bbc01.coutts.com",
		IpAddress: "52.84.20.193",
	},
	&Masquerade{
		Domain:    "1706bbc01.coutts.com",
		IpAddress: "54.192.73.151",
	},
	&Masquerade{
		Domain:    "1706bbc01.coutts.com",
		IpAddress: "54.230.2.76",
	},
	&Masquerade{
		Domain:    "1706bbc01.coutts.com",
		IpAddress: "54.192.23.144",
	},
	&Masquerade{
		Domain:    "1706bbc01.coutts.com",
		IpAddress: "54.192.26.174",
	},
	&Masquerade{
		Domain:    "1706bbc01.coutts.com",
		IpAddress: "52.222.130.128",
	},
	&Masquerade{
		Domain:    "1706bbc01.coutts.com",
		IpAddress: "52.222.200.21",
	},
	&Masquerade{
		Domain:    "1706bbc01.coutts.com",
		IpAddress: "54.230.53.226",
	},
	&Masquerade{
		Domain:    "1706bbc01.coutts.com",
		IpAddress: "205.251.223.236",
	},
	&Masquerade{
		Domain:    "1706bbc01.coutts.com",
		IpAddress: "52.84.78.192",
	},
	&Masquerade{
		Domain:    "1706bbc01.coutts.com",
		IpAddress: "54.192.49.50",
	},
	&Masquerade{
		Domain:    "1706bbc01.coutts.com",
		IpAddress: "54.230.30.14",
	},
	&Masquerade{
		Domain:    "1706bbc01.coutts.com",
		IpAddress: "54.230.78.203",
	},
	&Masquerade{
		Domain:    "1706bbc01.coutts.com",
		IpAddress: "54.239.176.134",
	},
	&Masquerade{
		Domain:    "1life.com",
		IpAddress: "52.84.24.97",
	},
	&Masquerade{
		Domain:    "1life.com",
		IpAddress: "52.222.151.172",
	},
	&Masquerade{
		Domain:    "1life.com",
		IpAddress: "52.222.189.177",
	},
	&Masquerade{
		Domain:    "1life.com",
		IpAddress: "54.240.190.146",
	},
	&Masquerade{
		Domain:    "1life.com",
		IpAddress: "204.246.164.124",
	},
	&Masquerade{
		Domain:    "1life.com",
		IpAddress: "54.192.48.66",
	},
	&Masquerade{
		Domain:    "1life.com",
		IpAddress: "54.230.14.228",
	},
	&Masquerade{
		Domain:    "1life.com",
		IpAddress: "52.84.79.237",
	},
	&Masquerade{
		Domain:    "1life.com",
		IpAddress: "54.192.23.236",
	},
	&Masquerade{
		Domain:    "1life.com",
		IpAddress: "13.32.26.241",
	},
	&Masquerade{
		Domain:    "1life.com",
		IpAddress: "52.222.197.173",
	},
	&Masquerade{
		Domain:    "1life.com",
		IpAddress: "54.192.47.167",
	},
	&Masquerade{
		Domain:    "1life.com",
		IpAddress: "52.84.32.78",
	},
	&Masquerade{
		Domain:    "1life.com",
		IpAddress: "54.192.24.200",
	},
	&Masquerade{
		Domain:    "1life.com",
		IpAddress: "54.192.6.192",
	},
	&Masquerade{
		Domain:    "1life.com",
		IpAddress: "52.84.5.66",
	},
	&Masquerade{
		Domain:    "1life.com",
		IpAddress: "54.230.78.48",
	},
	&Masquerade{
		Domain:    "1life.com",
		IpAddress: "54.230.10.56",
	},
	&Masquerade{
		Domain:    "1life.com",
		IpAddress: "54.230.58.188",
	},
	&Masquerade{
		Domain:    "1life.com",
		IpAddress: "52.84.62.37",
	},
	&Masquerade{
		Domain:    "1life.com",
		IpAddress: "54.230.2.52",
	},
	&Masquerade{
		Domain:    "1life.com",
		IpAddress: "54.230.39.70",
	},
	&Masquerade{
		Domain:    "1life.com",
		IpAddress: "54.192.19.213",
	},
	&Masquerade{
		Domain:    "1life.com",
		IpAddress: "205.251.207.196",
	},
	&Masquerade{
		Domain:    "1life.com",
		IpAddress: "54.192.74.86",
	},
	&Masquerade{
		Domain:    "1life.com",
		IpAddress: "54.239.164.243",
	},
	&Masquerade{
		Domain:    "1life.com",
		IpAddress: "52.222.169.207",
	},
	&Masquerade{
		Domain:    "1life.com",
		IpAddress: "52.222.130.104",
	},
	&Masquerade{
		Domain:    "1life.com",
		IpAddress: "13.32.7.163",
	},
	&Masquerade{
		Domain:    "1rx.io",
		IpAddress: "54.192.19.210",
	},
	&Masquerade{
		Domain:    "1rx.io",
		IpAddress: "54.192.44.156",
	},
	&Masquerade{
		Domain:    "1rx.io",
		IpAddress: "54.240.174.98",
	},
	&Masquerade{
		Domain:    "1rx.io",
		IpAddress: "52.84.80.42",
	},
	&Masquerade{
		Domain:    "1rx.io",
		IpAddress: "52.84.5.169",
	},
	&Masquerade{
		Domain:    "1rx.io",
		IpAddress: "52.84.51.77",
	},
	&Masquerade{
		Domain:    "1rx.io",
		IpAddress: "54.192.31.223",
	},
	&Masquerade{
		Domain:    "1rx.io",
		IpAddress: "54.230.72.93",
	},
	&Masquerade{
		Domain:    "1rx.io",
		IpAddress: "54.230.8.241",
	},
	&Masquerade{
		Domain:    "1rx.io",
		IpAddress: "54.192.5.128",
	},
	&Masquerade{
		Domain:    "1rx.io",
		IpAddress: "52.222.150.7",
	},
	&Masquerade{
		Domain:    "1rx.io",
		IpAddress: "54.192.49.175",
	},
	&Masquerade{
		Domain:    "1rx.io",
		IpAddress: "52.222.181.135",
	},
	&Masquerade{
		Domain:    "1rx.io",
		IpAddress: "13.32.9.157",
	},
	&Masquerade{
		Domain:    "1rx.io",
		IpAddress: "54.230.5.91",
	},
	&Masquerade{
		Domain:    "1rx.io",
		IpAddress: "54.192.15.76",
	},
	&Masquerade{
		Domain:    "1rx.io",
		IpAddress: "52.222.142.169",
	},
	&Masquerade{
		Domain:    "1rx.io",
		IpAddress: "52.222.204.250",
	},
	&Masquerade{
		Domain:    "1rx.io",
		IpAddress: "205.251.207.143",
	},
	&Masquerade{
		Domain:    "1rx.io",
		IpAddress: "52.84.1.196",
	},
	&Masquerade{
		Domain:    "1rx.io",
		IpAddress: "54.192.47.122",
	},
	&Masquerade{
		Domain:    "1rx.io",
		IpAddress: "52.84.65.86",
	},
	&Masquerade{
		Domain:    "1rx.io",
		IpAddress: "52.222.169.254",
	},
	&Masquerade{
		Domain:    "1rx.io",
		IpAddress: "54.192.63.119",
	},
	&Masquerade{
		Domain:    "1rx.io",
		IpAddress: "52.84.67.108",
	},
	&Masquerade{
		Domain:    "1rx.io",
		IpAddress: "13.32.23.201",
	},
	&Masquerade{
		Domain:    "1rx.io",
		IpAddress: "54.182.5.152",
	},
	&Masquerade{
		Domain:    "1rx.io",
		IpAddress: "54.192.77.117",
	},
	&Masquerade{
		Domain:    "1rx.io",
		IpAddress: "52.222.201.195",
	},
	&Masquerade{
		Domain:    "1rx.io",
		IpAddress: "54.230.55.160",
	},
	&Masquerade{
		Domain:    "1rx.io",
		IpAddress: "54.240.168.80",
	},
	&Masquerade{
		Domain:    "1rx.io",
		IpAddress: "54.192.75.118",
	},
	&Masquerade{
		Domain:    "1rx.io",
		IpAddress: "54.230.53.220",
	},
	&Masquerade{
		Domain:    "1rx.io",
		IpAddress: "52.222.166.24",
	},
	&Masquerade{
		Domain:    "1rx.io",
		IpAddress: "54.192.60.215",
	},
	&Masquerade{
		Domain:    "1rx.io",
		IpAddress: "52.222.156.204",
	},
	&Masquerade{
		Domain:    "1rx.io",
		IpAddress: "54.230.11.193",
	},
	&Masquerade{
		Domain:    "1rx.io",
		IpAddress: "205.251.207.146",
	},
	&Masquerade{
		Domain:    "1rx.io",
		IpAddress: "205.251.223.16",
	},
	&Masquerade{
		Domain:    "1rx.io",
		IpAddress: "52.84.32.57",
	},
	&Masquerade{
		Domain:    "1rx.io",
		IpAddress: "13.32.25.159",
	},
	&Masquerade{
		Domain:    "1rx.io",
		IpAddress: "52.84.17.47",
	},
	&Masquerade{
		Domain:    "1rx.io",
		IpAddress: "54.230.81.77",
	},
	&Masquerade{
		Domain:    "1rx.io",
		IpAddress: "54.230.14.59",
	},
	&Masquerade{
		Domain:    "1rx.io",
		IpAddress: "54.192.44.51",
	},
	&Masquerade{
		Domain:    "1rx.io",
		IpAddress: "52.84.37.69",
	},
	&Masquerade{
		Domain:    "1rx.io",
		IpAddress: "13.32.11.72",
	},
	&Masquerade{
		Domain:    "1rx.io",
		IpAddress: "52.222.187.214",
	},
	&Masquerade{
		Domain:    "1rx.io",
		IpAddress: "205.251.251.204",
	},
	&Masquerade{
		Domain:    "1rx.io",
		IpAddress: "54.192.79.203",
	},
	&Masquerade{
		Domain:    "1rx.io",
		IpAddress: "54.230.27.63",
	},
	&Masquerade{
		Domain:    "254a.com",
		IpAddress: "13.32.14.127",
	},
	&Masquerade{
		Domain:    "254a.com",
		IpAddress: "52.222.153.189",
	},
	&Masquerade{
		Domain:    "254a.com",
		IpAddress: "54.192.52.252",
	},
	&Masquerade{
		Domain:    "254a.com",
		IpAddress: "52.84.2.249",
	},
	&Masquerade{
		Domain:    "254a.com",
		IpAddress: "52.222.184.246",
	},
	&Masquerade{
		Domain:    "254a.com",
		IpAddress: "216.137.43.46",
	},
	&Masquerade{
		Domain:    "254a.com",
		IpAddress: "13.32.27.217",
	},
	&Masquerade{
		Domain:    "254a.com",
		IpAddress: "54.230.56.178",
	},
	&Masquerade{
		Domain:    "254a.com",
		IpAddress: "52.84.39.198",
	},
	&Masquerade{
		Domain:    "254a.com",
		IpAddress: "54.192.80.64",
	},
	&Masquerade{
		Domain:    "254a.com",
		IpAddress: "54.192.47.80",
	},
	&Masquerade{
		Domain:    "254a.com",
		IpAddress: "54.240.172.158",
	},
	&Masquerade{
		Domain:    "254a.com",
		IpAddress: "54.239.162.199",
	},
	&Masquerade{
		Domain:    "254a.com",
		IpAddress: "52.222.168.215",
	},
	&Masquerade{
		Domain:    "254a.com",
		IpAddress: "52.84.77.52",
	},
	&Masquerade{
		Domain:    "254a.com",
		IpAddress: "54.192.63.57",
	},
	&Masquerade{
		Domain:    "254a.com",
		IpAddress: "54.192.30.211",
	},
	&Masquerade{
		Domain:    "254a.com",
		IpAddress: "13.32.27.15",
	},
	&Masquerade{
		Domain:    "254a.com",
		IpAddress: "54.239.194.60",
	},
	&Masquerade{
		Domain:    "254a.com",
		IpAddress: "52.222.204.198",
	},
	&Masquerade{
		Domain:    "254a.com",
		IpAddress: "54.192.49.165",
	},
	&Masquerade{
		Domain:    "254a.com",
		IpAddress: "13.32.27.77",
	},
	&Masquerade{
		Domain:    "254a.com",
		IpAddress: "52.222.135.80",
	},
	&Masquerade{
		Domain:    "254a.com",
		IpAddress: "54.192.30.194",
	},
	&Masquerade{
		Domain:    "254a.com",
		IpAddress: "52.84.42.91",
	},
	&Masquerade{
		Domain:    "254a.com",
		IpAddress: "52.84.42.21",
	},
	&Masquerade{
		Domain:    "254a.com",
		IpAddress: "52.84.19.111",
	},
	&Masquerade{
		Domain:    "254a.com",
		IpAddress: "52.84.65.159",
	},
	&Masquerade{
		Domain:    "2cimple.com",
		IpAddress: "54.239.152.224",
	},
	&Masquerade{
		Domain:    "2cimple.com",
		IpAddress: "54.192.1.145",
	},
	&Masquerade{
		Domain:    "2cimple.com",
		IpAddress: "52.84.23.122",
	},
	&Masquerade{
		Domain:    "2cimple.com",
		IpAddress: "52.84.79.191",
	},
	&Masquerade{
		Domain:    "2cimple.com",
		IpAddress: "52.222.204.226",
	},
	&Masquerade{
		Domain:    "2cimple.com",
		IpAddress: "52.84.60.171",
	},
	&Masquerade{
		Domain:    "2cimple.com",
		IpAddress: "54.192.24.113",
	},
	&Masquerade{
		Domain:    "2cimple.com",
		IpAddress: "52.222.173.207",
	},
	&Masquerade{
		Domain:    "2cimple.com",
		IpAddress: "13.32.26.66",
	},
	&Masquerade{
		Domain:    "2cimple.com",
		IpAddress: "54.239.180.114",
	},
	&Masquerade{
		Domain:    "2cimple.com",
		IpAddress: "52.84.39.152",
	},
	&Masquerade{
		Domain:    "2cimple.com",
		IpAddress: "54.230.78.117",
	},
	&Masquerade{
		Domain:    "2cimple.com",
		IpAddress: "54.230.28.222",
	},
	&Masquerade{
		Domain:    "2cimple.com",
		IpAddress: "13.32.5.251",
	},
	&Masquerade{
		Domain:    "2cimple.com",
		IpAddress: "52.84.4.210",
	},
	&Masquerade{
		Domain:    "2cimple.com",
		IpAddress: "54.192.74.202",
	},
	&Masquerade{
		Domain:    "2cimple.com",
		IpAddress: "216.137.59.187",
	},
	&Masquerade{
		Domain:    "2cimple.com",
		IpAddress: "54.192.62.98",
	},
	&Masquerade{
		Domain:    "2cimple.com",
		IpAddress: "52.222.186.202",
	},
	&Masquerade{
		Domain:    "2cimple.com",
		IpAddress: "54.230.45.210",
	},
	&Masquerade{
		Domain:    "2cimple.com",
		IpAddress: "54.182.6.69",
	},
	&Masquerade{
		Domain:    "2cimple.com",
		IpAddress: "52.222.137.124",
	},
	&Masquerade{
		Domain:    "2cimple.com",
		IpAddress: "52.222.204.253",
	},
	&Masquerade{
		Domain:    "2cimple.com",
		IpAddress: "54.230.56.158",
	},
	&Masquerade{
		Domain:    "2cimple.com",
		IpAddress: "54.239.200.134",
	},
	&Masquerade{
		Domain:    "2cimple.com",
		IpAddress: "54.240.190.199",
	},
	&Masquerade{
		Domain:    "2cimple.com",
		IpAddress: "54.230.80.67",
	},
	&Masquerade{
		Domain:    "2cimple.com",
		IpAddress: "13.32.5.23",
	},
	&Masquerade{
		Domain:    "2cimple.com",
		IpAddress: "54.230.8.190",
	},
	&Masquerade{
		Domain:    "2cimple.com",
		IpAddress: "54.192.17.23",
	},
	&Masquerade{
		Domain:    "2cimple.com",
		IpAddress: "54.230.37.112",
	},
	&Masquerade{
		Domain:    "2cimple.com",
		IpAddress: "52.222.157.246",
	},
	&Masquerade{
		Domain:    "2cimple.com",
		IpAddress: "54.230.48.75",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "54.230.58.43",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "54.230.11.57",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "52.222.169.80",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "54.230.6.194",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "52.84.23.26",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "13.32.10.135",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "54.239.176.52",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "13.32.27.37",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "52.222.159.247",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "52.84.80.131",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "13.32.23.196",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "52.84.37.76",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "54.192.28.98",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "52.84.65.62",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "52.222.204.135",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "54.192.51.88",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "52.222.188.182",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "54.230.14.41",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "54.230.73.100",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "54.230.9.212",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "54.230.23.83",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "216.137.63.212",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "54.239.194.16",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "54.230.61.249",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "54.230.30.253",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "52.84.49.222",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "13.32.23.29",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "13.32.23.99",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "54.192.5.13",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "52.222.129.72",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "52.222.137.149",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "54.192.51.202",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "52.222.152.65",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "54.230.19.67",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "52.222.167.37",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "52.84.8.119",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "54.192.46.198",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "54.192.78.243",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "52.84.60.186",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "13.32.5.40",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "54.192.2.90",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "54.192.54.35",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "52.84.39.74",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "54.192.80.84",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "52.84.19.119",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "52.222.159.21",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "52.222.198.192",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "54.230.25.166",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "54.192.0.238",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "54.230.38.154",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "54.192.77.41",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "54.192.54.15",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "52.84.79.105",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "54.230.18.169",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "52.222.186.210",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "54.192.14.84",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "54.192.46.247",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "54.192.72.129",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "52.84.5.249",
	},
	&Masquerade{
		Domain:    "2u.com",
		IpAddress: "54.192.62.37",
	},
	&Masquerade{
		Domain:    "2xu.com",
		IpAddress: "205.251.253.36",
	},
	&Masquerade{
		Domain:    "2xu.com",
		IpAddress: "204.246.164.131",
	},
	&Masquerade{
		Domain:    "2xu.com",
		IpAddress: "54.192.58.218",
	},
	&Masquerade{
		Domain:    "2xu.com",
		IpAddress: "52.84.1.31",
	},
	&Masquerade{
		Domain:    "2xu.com",
		IpAddress: "54.230.4.95",
	},
	&Masquerade{
		Domain:    "2xu.com",
		IpAddress: "54.240.190.50",
	},
	&Masquerade{
		Domain:    "2xu.com",
		IpAddress: "52.222.155.23",
	},
	&Masquerade{
		Domain:    "2xu.com",
		IpAddress: "54.192.10.205",
	},
	&Masquerade{
		Domain:    "2xu.com",
		IpAddress: "13.32.13.252",
	},
	&Masquerade{
		Domain:    "2xu.com",
		IpAddress: "216.137.52.89",
	},
	&Masquerade{
		Domain:    "2xu.com",
		IpAddress: "52.84.76.8",
	},
	&Masquerade{
		Domain:    "2xu.com",
		IpAddress: "52.222.173.52",
	},
	&Masquerade{
		Domain:    "2xu.com",
		IpAddress: "54.230.77.126",
	},
	&Masquerade{
		Domain:    "2xu.com",
		IpAddress: "54.230.2.118",
	},
	&Masquerade{
		Domain:    "2xu.com",
		IpAddress: "13.32.21.252",
	},
	&Masquerade{
		Domain:    "2xu.com",
		IpAddress: "54.239.186.101",
	},
	&Masquerade{
		Domain:    "2xu.com",
		IpAddress: "54.230.47.81",
	},
	&Masquerade{
		Domain:    "2xu.com",
		IpAddress: "54.192.62.126",
	},
	&Masquerade{
		Domain:    "2xu.com",
		IpAddress: "54.230.27.237",
	},
	&Masquerade{
		Domain:    "2xu.com",
		IpAddress: "52.222.139.203",
	},
	&Masquerade{
		Domain:    "2xu.com",
		IpAddress: "52.222.155.19",
	},
	&Masquerade{
		Domain:    "2xu.com",
		IpAddress: "52.84.22.228",
	},
	&Masquerade{
		Domain:    "2xu.com",
		IpAddress: "54.230.49.115",
	},
	&Masquerade{
		Domain:    "2xu.com",
		IpAddress: "52.222.202.179",
	},
	&Masquerade{
		Domain:    "2xu.com",
		IpAddress: "52.84.34.108",
	},
	&Masquerade{
		Domain:    "2xu.com",
		IpAddress: "54.192.17.36",
	},
	&Masquerade{
		Domain:    "2xu.com",
		IpAddress: "54.230.28.185",
	},
	&Masquerade{
		Domain:    "2xu.com",
		IpAddress: "52.222.186.174",
	},
	&Masquerade{
		Domain:    "2xu.com",
		IpAddress: "52.84.47.79",
	},
	&Masquerade{
		Domain:    "2xu.com",
		IpAddress: "52.84.62.192",
	},
	&Masquerade{
		Domain:    "4fdaayvm7rrh2cz8-cdn.telematics-hv.uconnectservice.net",
		IpAddress: "52.84.1.143",
	},
	&Masquerade{
		Domain:    "4fdaayvm7rrh2cz8-cdn.telematics-hv.uconnectservice.net",
		IpAddress: "54.230.30.163",
	},
	&Masquerade{
		Domain:    "4fdaayvm7rrh2cz8-cdn.telematics-hv.uconnectservice.net",
		IpAddress: "54.230.5.41",
	},
	&Masquerade{
		Domain:    "4fdaayvm7rrh2cz8-cdn.telematics-hv.uconnectservice.net",
		IpAddress: "52.222.184.140",
	},
	&Masquerade{
		Domain:    "4fdaayvm7rrh2cz8-cdn.telematics-hv.uconnectservice.net",
		IpAddress: "54.230.52.39",
	},
	&Masquerade{
		Domain:    "4fdaayvm7rrh2cz8-cdn.telematics-hv.uconnectservice.net",
		IpAddress: "54.230.37.252",
	},
	&Masquerade{
		Domain:    "4fdaayvm7rrh2cz8-cdn.telematics-hv.uconnectservice.net",
		IpAddress: "52.84.17.151",
	},
	&Masquerade{
		Domain:    "4fdaayvm7rrh2cz8-cdn.telematics-hv.uconnectservice.net",
		IpAddress: "13.32.7.66",
	},
	&Masquerade{
		Domain:    "4fdaayvm7rrh2cz8-cdn.telematics-hv.uconnectservice.net",
		IpAddress: "52.222.148.254",
	},
	&Masquerade{
		Domain:    "4fdaayvm7rrh2cz8-cdn.telematics-hv.uconnectservice.net",
		IpAddress: "54.230.61.147",
	},
	&Masquerade{
		Domain:    "4fdaayvm7rrh2cz8-cdn.telematics-hv.uconnectservice.net",
		IpAddress: "52.84.80.192",
	},
	&Masquerade{
		Domain:    "4fdaayvm7rrh2cz8-cdn.telematics-hv.uconnectservice.net",
		IpAddress: "54.192.50.122",
	},
	&Masquerade{
		Domain:    "4fdaayvm7rrh2cz8-cdn.telematics-hv.uconnectservice.net",
		IpAddress: "54.230.25.13",
	},
	&Masquerade{
		Domain:    "4fdaayvm7rrh2cz8-cdn.telematics-hv.uconnectservice.net",
		IpAddress: "54.240.170.182",
	},
	&Masquerade{
		Domain:    "4fdaayvm7rrh2cz8-cdn.telematics-hv.uconnectservice.net",
		IpAddress: "52.84.30.125",
	},
	&Masquerade{
		Domain:    "4fdaayvm7rrh2cz8-cdn.telematics-hv.uconnectservice.net",
		IpAddress: "54.230.77.131",
	},
	&Masquerade{
		Domain:    "4fdaayvm7rrh2cz8-cdn.telematics-hv.uconnectservice.net",
		IpAddress: "54.230.56.117",
	},
	&Masquerade{
		Domain:    "4fdaayvm7rrh2cz8-cdn.telematics-hv.uconnectservice.net",
		IpAddress: "54.192.46.133",
	},
	&Masquerade{
		Domain:    "4fdaayvm7rrh2cz8-cdn.telematics-hv.uconnectservice.net",
		IpAddress: "52.84.42.119",
	},
	&Masquerade{
		Domain:    "4fdaayvm7rrh2cz8-cdn.telematics-hv.uconnectservice.net",
		IpAddress: "13.32.25.224",
	},
	&Masquerade{
		Domain:    "4fdaayvm7rrh2cz8-cdn.telematics-hv.uconnectservice.net",
		IpAddress: "52.222.139.225",
	},
	&Masquerade{
		Domain:    "4fdaayvm7rrh2cz8-cdn.telematics-hv.uconnectservice.net",
		IpAddress: "54.239.130.75",
	},
	&Masquerade{
		Domain:    "4fdaayvm7rrh2cz8-cdn.telematics-hv.uconnectservice.net",
		IpAddress: "54.192.1.45",
	},
	&Masquerade{
		Domain:    "4fdaayvm7rrh2cz8-cdn.telematics-hv.uconnectservice.net",
		IpAddress: "54.192.16.218",
	},
	&Masquerade{
		Domain:    "4fdaayvm7rrh2cz8-cdn.telematics-hv.uconnectservice.net",
		IpAddress: "54.239.164.8",
	},
	&Masquerade{
		Domain:    "4fdaayvm7rrh2cz8-cdn.telematics-hv.uconnectservice.net",
		IpAddress: "54.240.174.247",
	},
	&Masquerade{
		Domain:    "4fdaayvm7rrh2cz8-cdn.telematics-hv.uconnectservice.net",
		IpAddress: "52.84.59.172",
	},
	&Masquerade{
		Domain:    "4fdaayvm7rrh2cz8-cdn.telematics-hv.uconnectservice.net",
		IpAddress: "54.230.8.155",
	},
	&Masquerade{
		Domain:    "4fdaayvm7rrh2cz8-cdn.telematics-hv.uconnectservice.net",
		IpAddress: "52.222.198.31",
	},
	&Masquerade{
		Domain:    "4fdaayvm7rrh2cz8-cdn.telematics-hv.uconnectservice.net",
		IpAddress: "52.222.170.148",
	},
	&Masquerade{
		Domain:    "4v1game.net",
		IpAddress: "52.84.23.97",
	},
	&Masquerade{
		Domain:    "4v1game.net",
		IpAddress: "52.84.77.91",
	},
	&Masquerade{
		Domain:    "4v1game.net",
		IpAddress: "54.230.47.247",
	},
	&Masquerade{
		Domain:    "4v1game.net",
		IpAddress: "54.230.11.58",
	},
	&Masquerade{
		Domain:    "4v1game.net",
		IpAddress: "54.192.58.101",
	},
	&Masquerade{
		Domain:    "4v1game.net",
		IpAddress: "54.230.49.127",
	},
	&Masquerade{
		Domain:    "4v1game.net",
		IpAddress: "54.230.25.77",
	},
	&Masquerade{
		Domain:    "4v1game.net",
		IpAddress: "54.192.79.139",
	},
	&Masquerade{
		Domain:    "4v1game.net",
		IpAddress: "205.251.203.112",
	},
	&Masquerade{
		Domain:    "4v1game.net",
		IpAddress: "52.222.198.236",
	},
	&Masquerade{
		Domain:    "4v1game.net",
		IpAddress: "54.192.79.138",
	},
	&Masquerade{
		Domain:    "4v1game.net",
		IpAddress: "54.182.5.76",
	},
	&Masquerade{
		Domain:    "4v1game.net",
		IpAddress: "204.246.164.80",
	},
	&Masquerade{
		Domain:    "4v1game.net",
		IpAddress: "54.192.18.241",
	},
	&Masquerade{
		Domain:    "4v1game.net",
		IpAddress: "54.192.74.150",
	},
	&Masquerade{
		Domain:    "4v1game.net",
		IpAddress: "52.222.148.93",
	},
	&Masquerade{
		Domain:    "4v1game.net",
		IpAddress: "54.239.162.50",
	},
	&Masquerade{
		Domain:    "4v1game.net",
		IpAddress: "54.230.31.72",
	},
	&Masquerade{
		Domain:    "4v1game.net",
		IpAddress: "52.222.189.85",
	},
	&Masquerade{
		Domain:    "4v1game.net",
		IpAddress: "13.32.25.79",
	},
	&Masquerade{
		Domain:    "4v1game.net",
		IpAddress: "52.222.129.245",
	},
	&Masquerade{
		Domain:    "4v1game.net",
		IpAddress: "13.32.6.232",
	},
	&Masquerade{
		Domain:    "4v1game.net",
		IpAddress: "52.222.148.249",
	},
	&Masquerade{
		Domain:    "4v1game.net",
		IpAddress: "52.84.59.132",
	},
	&Masquerade{
		Domain:    "4v1game.net",
		IpAddress: "54.230.36.20",
	},
	&Masquerade{
		Domain:    "4v1game.net",
		IpAddress: "54.230.80.74",
	},
	&Masquerade{
		Domain:    "4v1game.net",
		IpAddress: "216.137.59.85",
	},
	&Masquerade{
		Domain:    "4v1game.net",
		IpAddress: "52.84.5.186",
	},
	&Masquerade{
		Domain:    "4v1game.net",
		IpAddress: "54.192.6.33",
	},
	&Masquerade{
		Domain:    "4v1game.net",
		IpAddress: "54.192.62.172",
	},
	&Masquerade{
		Domain:    "4v1game.net",
		IpAddress: "54.192.1.32",
	},
	&Masquerade{
		Domain:    "4v1game.net",
		IpAddress: "54.192.79.111",
	},
	&Masquerade{
		Domain:    "4v1game.net",
		IpAddress: "52.84.29.183",
	},
	&Masquerade{
		Domain:    "4v1game.net",
		IpAddress: "54.230.55.100",
	},
	&Masquerade{
		Domain:    "4v1game.net",
		IpAddress: "13.32.25.195",
	},
	&Masquerade{
		Domain:    "4v1game.net",
		IpAddress: "52.222.168.107",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "52.84.77.151",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "52.222.170.71",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "216.137.57.208",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "54.230.49.184",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "52.222.181.252",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "13.32.21.126",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "54.230.57.147",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "54.192.23.157",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "52.222.158.225",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "54.230.49.197",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "52.222.138.216",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "52.222.138.142",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "52.222.141.216",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "54.192.75.10",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "52.84.6.109",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "54.192.77.122",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "54.192.9.181",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "52.222.181.251",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "13.32.21.45",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "13.32.12.202",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "52.84.6.33",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "52.84.77.10",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "52.84.42.248",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "52.84.6.138",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "216.137.57.199",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "205.251.203.11",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "52.84.77.29",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "13.32.12.193",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "52.222.141.142",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "52.84.29.170",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "13.32.21.7",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "54.192.63.144",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "52.84.42.147",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "54.192.59.70",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "216.137.57.244",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "52.222.141.133",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "54.192.59.84",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "54.192.77.204",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "13.32.21.114",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "52.222.170.225",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "205.251.203.209",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "52.222.202.211",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "52.222.181.95",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "54.192.77.107",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "54.230.45.176",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "54.192.38.65",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "54.192.77.10",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "52.84.42.88",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "54.192.38.73",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "54.192.80.6",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "54.230.57.84",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "54.230.49.105",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "54.192.75.191",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "52.84.29.112",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "54.192.38.88",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "54.230.4.81",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "205.251.203.102",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "52.222.158.199",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "52.84.62.149",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "54.230.57.70",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "54.192.80.5",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "52.222.138.133",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "54.230.53.89",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "216.137.57.156",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "54.192.80.7",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "13.32.21.207",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "54.192.9.106",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "54.192.75.181",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "52.84.20.117",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "52.84.77.53",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "52.222.202.233",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "54.230.57.168",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "52.84.42.144",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "54.192.80.119",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "54.192.38.122",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "54.230.45.113",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "52.222.140.142",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "54.192.75.147",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "54.192.9.92",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "52.84.62.136",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "52.84.29.117",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "54.230.53.126",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "52.222.140.133",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "54.230.4.65",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "13.32.12.95",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "13.32.12.151",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "52.222.158.30",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "54.192.23.177",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "54.192.63.216",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "52.84.20.52",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "52.222.202.83",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "54.192.38.212",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "54.192.23.6",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "54.192.63.167",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "52.222.158.247",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "54.192.23.191",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "216.137.57.46",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "54.230.4.10",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "52.222.138.91",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "52.222.140.216",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "52.84.20.100",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "54.230.4.235",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "52.222.170.202",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "54.192.38.154",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "216.137.57.106",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "52.222.141.91",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "205.251.203.134",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "52.222.170.169",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "54.230.45.220",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "52.84.29.66",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "52.84.62.67",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "54.192.9.52",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "52.84.20.96",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "54.230.45.199",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "52.84.29.142",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "54.192.59.147",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "52.222.181.138",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "216.137.57.130",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "54.230.53.6",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "52.222.158.153",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "216.137.57.47",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "54.230.49.186",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "54.192.59.168",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "54.192.63.149",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "54.230.53.112",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "52.84.6.216",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "52.222.140.91",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "52.222.202.175",
	},
	&Masquerade{
		Domain:    "Images-na.ssl-images-amazon.com",
		IpAddress: "54.192.23.37",
	},
	&Masquerade{
		Domain:    "a-i-ad.com",
		IpAddress: "54.230.16.32",
	},
	&Masquerade{
		Domain:    "a-i-ad.com",
		IpAddress: "216.137.36.215",
	},
	&Masquerade{
		Domain:    "a-i-ad.com",
		IpAddress: "54.192.8.18",
	},
	&Masquerade{
		Domain:    "a-i-ad.com",
		IpAddress: "54.230.22.97",
	},
	&Masquerade{
		Domain:    "a-i-ad.com",
		IpAddress: "54.230.60.252",
	},
	&Masquerade{
		Domain:    "a-i-ad.com",
		IpAddress: "52.222.198.179",
	},
	&Masquerade{
		Domain:    "a-i-ad.com",
		IpAddress: "13.32.6.70",
	},
	&Masquerade{
		Domain:    "a-i-ad.com",
		IpAddress: "54.230.58.244",
	},
	&Masquerade{
		Domain:    "a-i-ad.com",
		IpAddress: "54.230.31.132",
	},
	&Masquerade{
		Domain:    "a-i-ad.com",
		IpAddress: "52.222.188.97",
	},
	&Masquerade{
		Domain:    "a-i-ad.com",
		IpAddress: "54.192.24.42",
	},
	&Masquerade{
		Domain:    "a-i-ad.com",
		IpAddress: "52.84.5.92",
	},
	&Masquerade{
		Domain:    "a-i-ad.com",
		IpAddress: "54.230.73.153",
	},
	&Masquerade{
		Domain:    "a-i-ad.com",
		IpAddress: "54.230.49.178",
	},
	&Masquerade{
		Domain:    "a-i-ad.com",
		IpAddress: "54.192.6.156",
	},
	&Masquerade{
		Domain:    "a-i-ad.com",
		IpAddress: "52.84.67.209",
	},
	&Masquerade{
		Domain:    "a-i-ad.com",
		IpAddress: "205.251.212.195",
	},
	&Masquerade{
		Domain:    "a-i-ad.com",
		IpAddress: "54.230.76.222",
	},
	&Masquerade{
		Domain:    "a-i-ad.com",
		IpAddress: "52.84.32.163",
	},
	&Masquerade{
		Domain:    "a-i-ad.com",
		IpAddress: "52.222.169.81",
	},
	&Masquerade{
		Domain:    "a-i-ad.com",
		IpAddress: "52.84.19.62",
	},
	&Masquerade{
		Domain:    "a-i-ad.com",
		IpAddress: "52.222.133.18",
	},
	&Masquerade{
		Domain:    "a-i-ad.com",
		IpAddress: "52.222.158.21",
	},
	&Masquerade{
		Domain:    "a-i-ad.com",
		IpAddress: "13.32.24.250",
	},
	&Masquerade{
		Domain:    "a-i-ad.com",
		IpAddress: "54.230.36.111",
	},
	&Masquerade{
		Domain:    "a-i-ad.com",
		IpAddress: "52.84.81.81",
	},
	&Masquerade{
		Domain:    "a-i-ad.com",
		IpAddress: "54.192.15.213",
	},
	&Masquerade{
		Domain:    "a-i-ad.com",
		IpAddress: "54.192.44.180",
	},
	&Masquerade{
		Domain:    "a-i-ad.com",
		IpAddress: "54.240.184.123",
	},
	&Masquerade{
		Domain:    "a-live.io",
		IpAddress: "52.84.13.51",
	},
	&Masquerade{
		Domain:    "a-live.io",
		IpAddress: "54.192.58.194",
	},
	&Masquerade{
		Domain:    "a-live.io",
		IpAddress: "54.230.75.78",
	},
	&Masquerade{
		Domain:    "a-live.io",
		IpAddress: "52.222.129.46",
	},
	&Masquerade{
		Domain:    "a-live.io",
		IpAddress: "204.246.164.4",
	},
	&Masquerade{
		Domain:    "a-live.io",
		IpAddress: "54.192.61.64",
	},
	&Masquerade{
		Domain:    "a-live.io",
		IpAddress: "54.192.13.155",
	},
	&Masquerade{
		Domain:    "a-live.io",
		IpAddress: "54.230.78.215",
	},
	&Masquerade{
		Domain:    "a-live.io",
		IpAddress: "13.32.27.13",
	},
	&Masquerade{
		Domain:    "a-live.io",
		IpAddress: "54.192.47.121",
	},
	&Masquerade{
		Domain:    "a-live.io",
		IpAddress: "52.84.23.36",
	},
	&Masquerade{
		Domain:    "a-live.io",
		IpAddress: "52.222.204.140",
	},
	&Masquerade{
		Domain:    "a-live.io",
		IpAddress: "13.32.27.194",
	},
	&Masquerade{
		Domain:    "a-live.io",
		IpAddress: "52.222.182.201",
	},
	&Masquerade{
		Domain:    "a-live.io",
		IpAddress: "52.84.65.91",
	},
	&Masquerade{
		Domain:    "a-live.io",
		IpAddress: "54.230.52.92",
	},
	&Masquerade{
		Domain:    "a-live.io",
		IpAddress: "54.192.16.151",
	},
	&Masquerade{
		Domain:    "a-live.io",
		IpAddress: "54.240.170.166",
	},
	&Masquerade{
		Domain:    "a-live.io",
		IpAddress: "52.84.33.92",
	},
	&Masquerade{
		Domain:    "a-live.io",
		IpAddress: "52.222.167.195",
	},
	&Masquerade{
		Domain:    "a-live.io",
		IpAddress: "13.32.12.165",
	},
	&Masquerade{
		Domain:    "a-live.io",
		IpAddress: "52.84.80.59",
	},
	&Masquerade{
		Domain:    "a-live.io",
		IpAddress: "54.230.4.189",
	},
	&Masquerade{
		Domain:    "a-live.io",
		IpAddress: "52.222.151.144",
	},
	&Masquerade{
		Domain:    "a-live.io",
		IpAddress: "54.192.10.214",
	},
	&Masquerade{
		Domain:    "a-live.io",
		IpAddress: "52.84.48.206",
	},
	&Masquerade{
		Domain:    "a.members.com",
		IpAddress: "52.222.198.36",
	},
	&Masquerade{
		Domain:    "a.members.com",
		IpAddress: "52.84.13.124",
	},
	&Masquerade{
		Domain:    "a.members.com",
		IpAddress: "54.192.10.166",
	},
	&Masquerade{
		Domain:    "a.members.com",
		IpAddress: "52.222.150.182",
	},
	&Masquerade{
		Domain:    "a.members.com",
		IpAddress: "54.192.51.192",
	},
	&Masquerade{
		Domain:    "a.members.com",
		IpAddress: "52.222.188.240",
	},
	&Masquerade{
		Domain:    "a.members.com",
		IpAddress: "54.230.78.106",
	},
	&Masquerade{
		Domain:    "a.members.com",
		IpAddress: "52.222.129.171",
	},
	&Masquerade{
		Domain:    "a.members.com",
		IpAddress: "216.137.45.63",
	},
	&Masquerade{
		Domain:    "a.members.com",
		IpAddress: "13.32.23.240",
	},
	&Masquerade{
		Domain:    "a.members.com",
		IpAddress: "54.230.73.154",
	},
	&Masquerade{
		Domain:    "a.members.com",
		IpAddress: "54.230.26.248",
	},
	&Masquerade{
		Domain:    "a.members.com",
		IpAddress: "52.84.77.226",
	},
	&Masquerade{
		Domain:    "a.members.com",
		IpAddress: "54.192.47.183",
	},
	&Masquerade{
		Domain:    "a.members.com",
		IpAddress: "54.192.17.212",
	},
	&Masquerade{
		Domain:    "a.members.com",
		IpAddress: "52.222.150.252",
	},
	&Masquerade{
		Domain:    "a.members.com",
		IpAddress: "54.230.37.134",
	},
	&Masquerade{
		Domain:    "a.members.com",
		IpAddress: "204.246.164.82",
	},
	&Masquerade{
		Domain:    "a.members.com",
		IpAddress: "52.84.28.157",
	},
	&Masquerade{
		Domain:    "a.members.com",
		IpAddress: "52.222.150.193",
	},
	&Masquerade{
		Domain:    "a.members.com",
		IpAddress: "54.192.54.54",
	},
	&Masquerade{
		Domain:    "a.members.com",
		IpAddress: "52.84.59.187",
	},
	&Masquerade{
		Domain:    "a.members.com",
		IpAddress: "13.32.5.213",
	},
	&Masquerade{
		Domain:    "a.members.com",
		IpAddress: "52.84.51.191",
	},
	&Masquerade{
		Domain:    "a.members.com",
		IpAddress: "54.230.6.48",
	},
	&Masquerade{
		Domain:    "a.members.com",
		IpAddress: "52.222.172.241",
	},
	&Masquerade{
		Domain:    "abcmouse.co.kr",
		IpAddress: "205.251.206.172",
	},
	&Masquerade{
		Domain:    "abcmouse.co.kr",
		IpAddress: "52.222.152.6",
	},
	&Masquerade{
		Domain:    "abcmouse.co.kr",
		IpAddress: "52.84.79.227",
	},
	&Masquerade{
		Domain:    "abcmouse.co.kr",
		IpAddress: "54.192.49.236",
	},
	&Masquerade{
		Domain:    "abcmouse.co.kr",
		IpAddress: "13.32.21.6",
	},
	&Masquerade{
		Domain:    "abcmouse.co.kr",
		IpAddress: "52.222.182.26",
	},
	&Masquerade{
		Domain:    "abcmouse.co.kr",
		IpAddress: "54.192.23.70",
	},
	&Masquerade{
		Domain:    "abcmouse.co.kr",
		IpAddress: "52.222.133.170",
	},
	&Masquerade{
		Domain:    "abcmouse.co.kr",
		IpAddress: "52.84.60.162",
	},
	&Masquerade{
		Domain:    "abcmouse.co.kr",
		IpAddress: "54.230.19.139",
	},
	&Masquerade{
		Domain:    "abcmouse.co.kr",
		IpAddress: "52.84.13.101",
	},
	&Masquerade{
		Domain:    "abcmouse.co.kr",
		IpAddress: "54.230.76.51",
	},
	&Masquerade{
		Domain:    "abcmouse.co.kr",
		IpAddress: "52.84.28.65",
	},
	&Masquerade{
		Domain:    "abcmouse.co.kr",
		IpAddress: "52.222.152.38",
	},
	&Masquerade{
		Domain:    "abcmouse.co.kr",
		IpAddress: "54.230.55.154",
	},
	&Masquerade{
		Domain:    "abcmouse.co.kr",
		IpAddress: "13.32.6.251",
	},
	&Masquerade{
		Domain:    "abcmouse.co.kr",
		IpAddress: "52.84.42.39",
	},
	&Masquerade{
		Domain:    "abcmouse.co.kr",
		IpAddress: "54.230.19.27",
	},
	&Masquerade{
		Domain:    "abcmouse.co.kr",
		IpAddress: "52.84.18.104",
	},
	&Masquerade{
		Domain:    "abcmouse.co.kr",
		IpAddress: "52.222.170.147",
	},
	&Masquerade{
		Domain:    "abcmouse.co.kr",
		IpAddress: "54.230.57.180",
	},
	&Masquerade{
		Domain:    "abcmouse.co.kr",
		IpAddress: "54.192.10.187",
	},
	&Masquerade{
		Domain:    "abcmouse.co.kr",
		IpAddress: "54.230.30.53",
	},
	&Masquerade{
		Domain:    "abcmouse.co.kr",
		IpAddress: "54.192.59.180",
	},
	&Masquerade{
		Domain:    "abcmouse.co.kr",
		IpAddress: "54.239.152.193",
	},
	&Masquerade{
		Domain:    "abcmouse.co.kr",
		IpAddress: "54.239.200.58",
	},
	&Masquerade{
		Domain:    "abcmouse.co.kr",
		IpAddress: "54.239.162.232",
	},
	&Masquerade{
		Domain:    "abcmouse.co.kr",
		IpAddress: "54.230.22.95",
	},
	&Masquerade{
		Domain:    "abcmouse.co.kr",
		IpAddress: "54.192.24.30",
	},
	&Masquerade{
		Domain:    "abcmouse.co.kr",
		IpAddress: "54.230.38.112",
	},
	&Masquerade{
		Domain:    "abcmouse.co.kr",
		IpAddress: "54.192.1.70",
	},
	&Masquerade{
		Domain:    "abcmouse.co.kr",
		IpAddress: "52.222.202.52",
	},
	&Masquerade{
		Domain:    "abcmouse.co.kr",
		IpAddress: "54.192.62.57",
	},
	&Masquerade{
		Domain:    "abcmouse.com",
		IpAddress: "216.137.45.228",
	},
	&Masquerade{
		Domain:    "abcmouse.com",
		IpAddress: "54.192.17.139",
	},
	&Masquerade{
		Domain:    "abcmouse.com",
		IpAddress: "52.222.188.13",
	},
	&Masquerade{
		Domain:    "abcmouse.com",
		IpAddress: "54.230.73.204",
	},
	&Masquerade{
		Domain:    "abcmouse.com",
		IpAddress: "54.230.2.254",
	},
	&Masquerade{
		Domain:    "abcmouse.com",
		IpAddress: "205.251.207.31",
	},
	&Masquerade{
		Domain:    "abcmouse.com",
		IpAddress: "54.230.58.251",
	},
	&Masquerade{
		Domain:    "abcmouse.com",
		IpAddress: "54.192.63.243",
	},
	&Masquerade{
		Domain:    "abcmouse.com",
		IpAddress: "52.222.151.153",
	},
	&Masquerade{
		Domain:    "abcmouse.com",
		IpAddress: "54.182.7.189",
	},
	&Masquerade{
		Domain:    "abcmouse.com",
		IpAddress: "54.192.48.189",
	},
	&Masquerade{
		Domain:    "abcmouse.com",
		IpAddress: "52.222.202.19",
	},
	&Masquerade{
		Domain:    "abcmouse.com",
		IpAddress: "52.222.166.157",
	},
	&Masquerade{
		Domain:    "abcmouse.com",
		IpAddress: "13.32.26.207",
	},
	&Masquerade{
		Domain:    "abcmouse.com",
		IpAddress: "54.192.53.156",
	},
	&Masquerade{
		Domain:    "abcmouse.com",
		IpAddress: "52.84.8.189",
	},
	&Masquerade{
		Domain:    "abcmouse.com",
		IpAddress: "54.192.79.83",
	},
	&Masquerade{
		Domain:    "abcmouse.com",
		IpAddress: "52.84.51.142",
	},
	&Masquerade{
		Domain:    "abcmouse.com",
		IpAddress: "54.240.168.85",
	},
	&Masquerade{
		Domain:    "abcmouse.com",
		IpAddress: "52.84.29.171",
	},
	&Masquerade{
		Domain:    "abcmouse.com",
		IpAddress: "54.239.180.154",
	},
	&Masquerade{
		Domain:    "abcmouse.com",
		IpAddress: "13.32.12.124",
	},
	&Masquerade{
		Domain:    "abcmouse.com",
		IpAddress: "54.192.26.59",
	},
	&Masquerade{
		Domain:    "abcmouse.com",
		IpAddress: "54.192.9.97",
	},
	&Masquerade{
		Domain:    "abcmouse.com",
		IpAddress: "52.222.137.182",
	},
	&Masquerade{
		Domain:    "abcmouse.com",
		IpAddress: "54.230.47.133",
	},
	&Masquerade{
		Domain:    "abcmouse.com",
		IpAddress: "52.84.79.28",
	},
	&Masquerade{
		Domain:    "abcmouse.com",
		IpAddress: "54.192.39.81",
	},
	&Masquerade{
		Domain:    "abcmouse.com",
		IpAddress: "52.222.151.220",
	},
	&Masquerade{
		Domain:    "abcmouse.com",
		IpAddress: "54.240.170.135",
	},
	&Masquerade{
		Domain:    "abcmouse.com",
		IpAddress: "52.84.60.249",
	},
	&Masquerade{
		Domain:    "abcmouse.com",
		IpAddress: "54.239.180.138",
	},
	&Masquerade{
		Domain:    "abcmouse.com",
		IpAddress: "54.230.28.234",
	},
	&Masquerade{
		Domain:    "abcmouse.tw",
		IpAddress: "52.222.173.9",
	},
	&Masquerade{
		Domain:    "abcmouse.tw",
		IpAddress: "54.230.80.116",
	},
	&Masquerade{
		Domain:    "abcmouse.tw",
		IpAddress: "54.230.45.196",
	},
	&Masquerade{
		Domain:    "abcmouse.tw",
		IpAddress: "54.192.10.171",
	},
	&Masquerade{
		Domain:    "abcmouse.tw",
		IpAddress: "54.230.56.85",
	},
	&Masquerade{
		Domain:    "abcmouse.tw",
		IpAddress: "52.222.153.227",
	},
	&Masquerade{
		Domain:    "abcmouse.tw",
		IpAddress: "13.32.23.178",
	},
	&Masquerade{
		Domain:    "abcmouse.tw",
		IpAddress: "52.222.202.72",
	},
	&Masquerade{
		Domain:    "abcmouse.tw",
		IpAddress: "205.251.206.141",
	},
	&Masquerade{
		Domain:    "abcmouse.tw",
		IpAddress: "52.84.1.103",
	},
	&Masquerade{
		Domain:    "abcmouse.tw",
		IpAddress: "54.192.49.21",
	},
	&Masquerade{
		Domain:    "abcmouse.tw",
		IpAddress: "52.84.77.97",
	},
	&Masquerade{
		Domain:    "abcmouse.tw",
		IpAddress: "54.240.168.171",
	},
	&Masquerade{
		Domain:    "abcmouse.tw",
		IpAddress: "52.222.137.224",
	},
	&Masquerade{
		Domain:    "abcmouse.tw",
		IpAddress: "52.84.51.126",
	},
	&Masquerade{
		Domain:    "abcmouse.tw",
		IpAddress: "52.84.39.124",
	},
	&Masquerade{
		Domain:    "abcmouse.tw",
		IpAddress: "54.239.162.252",
	},
	&Masquerade{
		Domain:    "abcmouse.tw",
		IpAddress: "54.230.14.216",
	},
	&Masquerade{
		Domain:    "abcmouse.tw",
		IpAddress: "52.84.60.205",
	},
	&Masquerade{
		Domain:    "abcmouse.tw",
		IpAddress: "54.230.63.224",
	},
	&Masquerade{
		Domain:    "abcmouse.tw",
		IpAddress: "54.230.27.174",
	},
	&Masquerade{
		Domain:    "abcmouse.tw",
		IpAddress: "54.230.76.67",
	},
	&Masquerade{
		Domain:    "abcmouse.tw",
		IpAddress: "54.192.1.141",
	},
	&Masquerade{
		Domain:    "abcmouse.tw",
		IpAddress: "52.84.47.163",
	},
	&Masquerade{
		Domain:    "abcmouse.tw",
		IpAddress: "54.192.31.218",
	},
	&Masquerade{
		Domain:    "abcmouse.tw",
		IpAddress: "54.192.6.240",
	},
	&Masquerade{
		Domain:    "abcmouse.tw",
		IpAddress: "54.230.19.208",
	},
	&Masquerade{
		Domain:    "abcmouse.tw",
		IpAddress: "54.230.55.93",
	},
	&Masquerade{
		Domain:    "abcmouse.tw",
		IpAddress: "54.182.6.153",
	},
	&Masquerade{
		Domain:    "abcmouse.tw",
		IpAddress: "54.239.164.191",
	},
	&Masquerade{
		Domain:    "abcmouse.tw",
		IpAddress: "13.32.13.118",
	},
	&Masquerade{
		Domain:    "abcmouse.tw",
		IpAddress: "52.222.184.153",
	},
	&Masquerade{
		Domain:    "abtasty.com",
		IpAddress: "205.251.223.57",
	},
	&Masquerade{
		Domain:    "abtasty.com",
		IpAddress: "52.222.155.248",
	},
	&Masquerade{
		Domain:    "abtasty.com",
		IpAddress: "52.84.67.81",
	},
	&Masquerade{
		Domain:    "abtasty.com",
		IpAddress: "54.192.78.183",
	},
	&Masquerade{
		Domain:    "abtasty.com",
		IpAddress: "52.84.24.8",
	},
	&Masquerade{
		Domain:    "abtasty.com",
		IpAddress: "54.239.142.157",
	},
	&Masquerade{
		Domain:    "abtasty.com",
		IpAddress: "52.84.80.199",
	},
	&Masquerade{
		Domain:    "abtasty.com",
		IpAddress: "54.230.39.110",
	},
	&Masquerade{
		Domain:    "abtasty.com",
		IpAddress: "52.222.175.203",
	},
	&Masquerade{
		Domain:    "abtasty.com",
		IpAddress: "54.230.53.203",
	},
	&Masquerade{
		Domain:    "abtasty.com",
		IpAddress: "54.240.162.142",
	},
	&Masquerade{
		Domain:    "abtasty.com",
		IpAddress: "52.222.188.214",
	},
	&Masquerade{
		Domain:    "abtasty.com",
		IpAddress: "205.251.219.43",
	},
	&Masquerade{
		Domain:    "abtasty.com",
		IpAddress: "54.230.73.114",
	},
	&Masquerade{
		Domain:    "abtasty.com",
		IpAddress: "13.32.11.201",
	},
	&Masquerade{
		Domain:    "abtasty.com",
		IpAddress: "52.222.137.136",
	},
	&Masquerade{
		Domain:    "abtasty.com",
		IpAddress: "54.230.23.90",
	},
	&Masquerade{
		Domain:    "abtasty.com",
		IpAddress: "52.222.199.178",
	},
	&Masquerade{
		Domain:    "abtasty.com",
		IpAddress: "205.251.203.124",
	},
	&Masquerade{
		Domain:    "abtasty.com",
		IpAddress: "54.230.17.213",
	},
	&Masquerade{
		Domain:    "abtasty.com",
		IpAddress: "54.192.8.212",
	},
	&Masquerade{
		Domain:    "abtasty.com",
		IpAddress: "54.230.63.37",
	},
	&Masquerade{
		Domain:    "abtasty.com",
		IpAddress: "54.230.31.223",
	},
	&Masquerade{
		Domain:    "abtasty.com",
		IpAddress: "54.192.1.72",
	},
	&Masquerade{
		Domain:    "abtasty.com",
		IpAddress: "13.32.22.124",
	},
	&Masquerade{
		Domain:    "abtasty.com",
		IpAddress: "205.251.223.168",
	},
	&Masquerade{
		Domain:    "abtasty.com",
		IpAddress: "54.192.50.8",
	},
	&Masquerade{
		Domain:    "abtasty.com",
		IpAddress: "54.192.4.158",
	},
	&Masquerade{
		Domain:    "abtasty.com",
		IpAddress: "54.192.14.55",
	},
	&Masquerade{
		Domain:    "abtasty.com",
		IpAddress: "52.84.8.116",
	},
	&Masquerade{
		Domain:    "abtasty.com",
		IpAddress: "52.84.37.137",
	},
	&Masquerade{
		Domain:    "abundo.osp.tech",
		IpAddress: "54.192.6.150",
	},
	&Masquerade{
		Domain:    "abundo.osp.tech",
		IpAddress: "54.239.194.59",
	},
	&Masquerade{
		Domain:    "abundo.osp.tech",
		IpAddress: "54.230.60.131",
	},
	&Masquerade{
		Domain:    "abundo.osp.tech",
		IpAddress: "52.84.2.60",
	},
	&Masquerade{
		Domain:    "abundo.osp.tech",
		IpAddress: "54.230.48.47",
	},
	&Masquerade{
		Domain:    "abundo.osp.tech",
		IpAddress: "52.222.141.75",
	},
	&Masquerade{
		Domain:    "abundo.osp.tech",
		IpAddress: "52.222.138.75",
	},
	&Masquerade{
		Domain:    "abundo.osp.tech",
		IpAddress: "54.230.52.105",
	},
	&Masquerade{
		Domain:    "abundo.osp.tech",
		IpAddress: "52.84.24.25",
	},
	&Masquerade{
		Domain:    "abundo.osp.tech",
		IpAddress: "52.222.153.203",
	},
	&Masquerade{
		Domain:    "abundo.osp.tech",
		IpAddress: "54.230.26.29",
	},
	&Masquerade{
		Domain:    "abundo.osp.tech",
		IpAddress: "54.230.17.206",
	},
	&Masquerade{
		Domain:    "abundo.osp.tech",
		IpAddress: "52.222.170.87",
	},
	&Masquerade{
		Domain:    "abundo.osp.tech",
		IpAddress: "54.192.46.57",
	},
	&Masquerade{
		Domain:    "abundo.osp.tech",
		IpAddress: "54.230.80.148",
	},
	&Masquerade{
		Domain:    "abundo.osp.tech",
		IpAddress: "54.192.57.229",
	},
	&Masquerade{
		Domain:    "abundo.osp.tech",
		IpAddress: "54.192.30.74",
	},
	&Masquerade{
		Domain:    "abundo.osp.tech",
		IpAddress: "52.222.201.165",
	},
	&Masquerade{
		Domain:    "abundo.osp.tech",
		IpAddress: "54.230.12.132",
	},
	&Masquerade{
		Domain:    "abundo.osp.tech",
		IpAddress: "54.192.76.168",
	},
	&Masquerade{
		Domain:    "abundo.osp.tech",
		IpAddress: "52.84.39.217",
	},
	&Masquerade{
		Domain:    "abundo.osp.tech",
		IpAddress: "52.84.62.157",
	},
	&Masquerade{
		Domain:    "abundo.osp.tech",
		IpAddress: "52.222.186.179",
	},
	&Masquerade{
		Domain:    "abundo.osp.tech",
		IpAddress: "52.222.153.150",
	},
	&Masquerade{
		Domain:    "abundo.osp.tech",
		IpAddress: "13.32.18.183",
	},
	&Masquerade{
		Domain:    "abundo.osp.tech",
		IpAddress: "52.222.140.75",
	},
	&Masquerade{
		Domain:    "abundo.osp.tech",
		IpAddress: "54.192.38.247",
	},
	&Masquerade{
		Domain:    "abundo.osp.tech",
		IpAddress: "52.222.153.41",
	},
	&Masquerade{
		Domain:    "abundo.osp.tech",
		IpAddress: "13.32.7.239",
	},
	&Masquerade{
		Domain:    "abundo.osp.tech",
		IpAddress: "54.182.6.151",
	},
	&Masquerade{
		Domain:    "ac.dropboxstatic.com",
		IpAddress: "54.192.19.191",
	},
	&Masquerade{
		Domain:    "ac.dropboxstatic.com",
		IpAddress: "52.222.198.81",
	},
	&Masquerade{
		Domain:    "ac.dropboxstatic.com",
		IpAddress: "54.192.8.139",
	},
	&Masquerade{
		Domain:    "ac.dropboxstatic.com",
		IpAddress: "54.230.75.138",
	},
	&Masquerade{
		Domain:    "ac.dropboxstatic.com",
		IpAddress: "54.230.3.37",
	},
	&Masquerade{
		Domain:    "ac.dropboxstatic.com",
		IpAddress: "54.240.172.196",
	},
	&Masquerade{
		Domain:    "ac.dropboxstatic.com",
		IpAddress: "13.32.26.95",
	},
	&Masquerade{
		Domain:    "ac.dropboxstatic.com",
		IpAddress: "52.84.4.7",
	},
	&Masquerade{
		Domain:    "ac.dropboxstatic.com",
		IpAddress: "52.222.175.17",
	},
	&Masquerade{
		Domain:    "ac.dropboxstatic.com",
		IpAddress: "54.192.53.167",
	},
	&Masquerade{
		Domain:    "ac.dropboxstatic.com",
		IpAddress: "54.230.80.35",
	},
	&Masquerade{
		Domain:    "ac.dropboxstatic.com",
		IpAddress: "52.222.184.240",
	},
	&Masquerade{
		Domain:    "ac.dropboxstatic.com",
		IpAddress: "54.230.46.45",
	},
	&Masquerade{
		Domain:    "ac.dropboxstatic.com",
		IpAddress: "54.192.60.144",
	},
	&Masquerade{
		Domain:    "ac.dropboxstatic.com",
		IpAddress: "204.246.169.31",
	},
	&Masquerade{
		Domain:    "ac.dropboxstatic.com",
		IpAddress: "52.84.61.83",
	},
	&Masquerade{
		Domain:    "ac.dropboxstatic.com",
		IpAddress: "54.230.26.133",
	},
	&Masquerade{
		Domain:    "ac.dropboxstatic.com",
		IpAddress: "52.84.79.213",
	},
	&Masquerade{
		Domain:    "ac.dropboxstatic.com",
		IpAddress: "54.239.164.133",
	},
	&Masquerade{
		Domain:    "ac.dropboxstatic.com",
		IpAddress: "54.192.57.66",
	},
	&Masquerade{
		Domain:    "ac.dropboxstatic.com",
		IpAddress: "54.182.6.36",
	},
	&Masquerade{
		Domain:    "ac.dropboxstatic.com",
		IpAddress: "52.222.154.127",
	},
	&Masquerade{
		Domain:    "ac.dropboxstatic.com",
		IpAddress: "54.192.6.251",
	},
	&Masquerade{
		Domain:    "ac.dropboxstatic.com",
		IpAddress: "216.137.57.178",
	},
	&Masquerade{
		Domain:    "ac.dropboxstatic.com",
		IpAddress: "52.222.137.169",
	},
	&Masquerade{
		Domain:    "ac.dropboxstatic.com",
		IpAddress: "13.32.10.209",
	},
	&Masquerade{
		Domain:    "ac.dropboxstatic.com",
		IpAddress: "52.84.39.211",
	},
	&Masquerade{
		Domain:    "ac.dropboxstatic.com",
		IpAddress: "52.84.20.171",
	},
	&Masquerade{
		Domain:    "ac.dropboxstatic.com",
		IpAddress: "54.239.194.224",
	},
	&Masquerade{
		Domain:    "ac.dropboxstatic.com",
		IpAddress: "52.222.154.81",
	},
	&Masquerade{
		Domain:    "access.oup.com",
		IpAddress: "52.84.66.7",
	},
	&Masquerade{
		Domain:    "access.oup.com",
		IpAddress: "52.84.13.153",
	},
	&Masquerade{
		Domain:    "access.oup.com",
		IpAddress: "205.251.206.16",
	},
	&Masquerade{
		Domain:    "access.oup.com",
		IpAddress: "54.192.78.112",
	},
	&Masquerade{
		Domain:    "access.oup.com",
		IpAddress: "52.84.56.7",
	},
	&Masquerade{
		Domain:    "access.oup.com",
		IpAddress: "52.84.64.7",
	},
	&Masquerade{
		Domain:    "access.oup.com",
		IpAddress: "13.32.7.145",
	},
	&Masquerade{
		Domain:    "access.oup.com",
		IpAddress: "52.222.189.91",
	},
	&Masquerade{
		Domain:    "access.oup.com",
		IpAddress: "205.251.253.154",
	},
	&Masquerade{
		Domain:    "access.oup.com",
		IpAddress: "54.240.174.158",
	},
	&Masquerade{
		Domain:    "access.oup.com",
		IpAddress: "54.192.6.173",
	},
	&Masquerade{
		Domain:    "access.oup.com",
		IpAddress: "52.222.152.95",
	},
	&Masquerade{
		Domain:    "access.oup.com",
		IpAddress: "52.222.134.145",
	},
	&Masquerade{
		Domain:    "access.oup.com",
		IpAddress: "54.230.18.129",
	},
	&Masquerade{
		Domain:    "access.oup.com",
		IpAddress: "205.251.251.94",
	},
	&Masquerade{
		Domain:    "access.oup.com",
		IpAddress: "216.137.59.77",
	},
	&Masquerade{
		Domain:    "access.oup.com",
		IpAddress: "54.230.60.108",
	},
	&Masquerade{
		Domain:    "access.oup.com",
		IpAddress: "54.192.1.66",
	},
	&Masquerade{
		Domain:    "access.oup.com",
		IpAddress: "52.84.75.150",
	},
	&Masquerade{
		Domain:    "access.oup.com",
		IpAddress: "13.32.26.94",
	},
	&Masquerade{
		Domain:    "access.oup.com",
		IpAddress: "52.222.197.104",
	},
	&Masquerade{
		Domain:    "access.oup.com",
		IpAddress: "54.192.26.122",
	},
	&Masquerade{
		Domain:    "access.oup.com",
		IpAddress: "54.230.80.247",
	},
	&Masquerade{
		Domain:    "access.oup.com",
		IpAddress: "52.84.30.176",
	},
	&Masquerade{
		Domain:    "access.oup.com",
		IpAddress: "54.192.74.223",
	},
	&Masquerade{
		Domain:    "access.oup.com",
		IpAddress: "54.230.22.198",
	},
	&Masquerade{
		Domain:    "access.oup.com",
		IpAddress: "52.84.20.222",
	},
	&Masquerade{
		Domain:    "access.oup.com",
		IpAddress: "54.192.47.98",
	},
	&Masquerade{
		Domain:    "access.oup.com",
		IpAddress: "52.222.172.178",
	},
	&Masquerade{
		Domain:    "accessiq.sailpoint.com",
		IpAddress: "52.222.139.72",
	},
	&Masquerade{
		Domain:    "accessiq.sailpoint.com",
		IpAddress: "52.84.11.193",
	},
	&Masquerade{
		Domain:    "accessiq.sailpoint.com",
		IpAddress: "52.84.24.6",
	},
	&Masquerade{
		Domain:    "accessiq.sailpoint.com",
		IpAddress: "52.222.156.15",
	},
	&Masquerade{
		Domain:    "accessiq.sailpoint.com",
		IpAddress: "52.222.172.250",
	},
	&Masquerade{
		Domain:    "accessiq.sailpoint.com",
		IpAddress: "54.230.8.177",
	},
	&Masquerade{
		Domain:    "accessiq.sailpoint.com",
		IpAddress: "13.32.18.204",
	},
	&Masquerade{
		Domain:    "accessiq.sailpoint.com",
		IpAddress: "205.251.215.181",
	},
	&Masquerade{
		Domain:    "accessiq.sailpoint.com",
		IpAddress: "54.192.62.22",
	},
	&Masquerade{
		Domain:    "accessiq.sailpoint.com",
		IpAddress: "52.84.29.31",
	},
	&Masquerade{
		Domain:    "accessiq.sailpoint.com",
		IpAddress: "13.32.18.55",
	},
	&Masquerade{
		Domain:    "accessiq.sailpoint.com",
		IpAddress: "54.230.28.173",
	},
	&Masquerade{
		Domain:    "accessiq.sailpoint.com",
		IpAddress: "13.32.10.26",
	},
	&Masquerade{
		Domain:    "accessiq.sailpoint.com",
		IpAddress: "216.137.36.142",
	},
	&Masquerade{
		Domain:    "accessiq.sailpoint.com",
		IpAddress: "54.230.4.50",
	},
	&Masquerade{
		Domain:    "accessiq.sailpoint.com",
		IpAddress: "52.222.172.11",
	},
	&Masquerade{
		Domain:    "accessiq.sailpoint.com",
		IpAddress: "54.239.186.35",
	},
	&Masquerade{
		Domain:    "accessiq.sailpoint.com",
		IpAddress: "52.222.186.33",
	},
	&Masquerade{
		Domain:    "accessiq.sailpoint.com",
		IpAddress: "52.84.60.165",
	},
	&Masquerade{
		Domain:    "accessiq.sailpoint.com",
		IpAddress: "52.84.78.171",
	},
	&Masquerade{
		Domain:    "accessiq.sailpoint.com",
		IpAddress: "54.192.49.234",
	},
	&Masquerade{
		Domain:    "accessiq.sailpoint.com",
		IpAddress: "54.192.72.175",
	},
	&Masquerade{
		Domain:    "accessiq.sailpoint.com",
		IpAddress: "54.230.54.122",
	},
	&Masquerade{
		Domain:    "accessiq.sailpoint.com",
		IpAddress: "54.230.14.251",
	},
	&Masquerade{
		Domain:    "accessiq.sailpoint.com",
		IpAddress: "205.251.206.190",
	},
	&Masquerade{
		Domain:    "accessiq.sailpoint.com",
		IpAddress: "54.230.27.83",
	},
	&Masquerade{
		Domain:    "accessiq.sailpoint.com",
		IpAddress: "52.84.14.193",
	},
	&Masquerade{
		Domain:    "accessiq.sailpoint.com",
		IpAddress: "54.192.79.48",
	},
	&Masquerade{
		Domain:    "accessiq.sailpoint.com",
		IpAddress: "54.192.1.233",
	},
	&Masquerade{
		Domain:    "accessiq.sailpoint.com",
		IpAddress: "54.239.216.36",
	},
	&Masquerade{
		Domain:    "accessiq.sailpoint.com",
		IpAddress: "52.84.47.5",
	},
	&Masquerade{
		Domain:    "accessiq.sailpoint.com",
		IpAddress: "54.192.58.132",
	},
	&Masquerade{
		Domain:    "accessiq.sailpoint.com",
		IpAddress: "54.230.45.120",
	},
	&Masquerade{
		Domain:    "accessiq.sailpoint.com",
		IpAddress: "52.222.203.201",
	},
	&Masquerade{
		Domain:    "accessiq.sailpoint.com",
		IpAddress: "54.230.38.175",
	},
	&Masquerade{
		Domain:    "accessiq.sailpoint.com",
		IpAddress: "52.222.156.145",
	},
	&Masquerade{
		Domain:    "accounts.hellocdn.net",
		IpAddress: "54.240.168.165",
	},
	&Masquerade{
		Domain:    "accounts.hellocdn.net",
		IpAddress: "52.84.5.130",
	},
	&Masquerade{
		Domain:    "accounts.hellocdn.net",
		IpAddress: "52.84.37.130",
	},
	&Masquerade{
		Domain:    "accounts.hellocdn.net",
		IpAddress: "216.137.45.231",
	},
	&Masquerade{
		Domain:    "accounts.hellocdn.net",
		IpAddress: "52.222.159.246",
	},
	&Masquerade{
		Domain:    "accounts.hellocdn.net",
		IpAddress: "54.230.3.64",
	},
	&Masquerade{
		Domain:    "accounts.hellocdn.net",
		IpAddress: "52.222.204.92",
	},
	&Masquerade{
		Domain:    "accounts.hellocdn.net",
		IpAddress: "52.84.19.182",
	},
	&Masquerade{
		Domain:    "accounts.hellocdn.net",
		IpAddress: "52.222.182.114",
	},
	&Masquerade{
		Domain:    "accounts.hellocdn.net",
		IpAddress: "52.222.141.92",
	},
	&Masquerade{
		Domain:    "accounts.hellocdn.net",
		IpAddress: "54.230.75.197",
	},
	&Masquerade{
		Domain:    "accounts.hellocdn.net",
		IpAddress: "54.192.6.70",
	},
	&Masquerade{
		Domain:    "accounts.hellocdn.net",
		IpAddress: "54.230.48.55",
	},
	&Masquerade{
		Domain:    "accounts.hellocdn.net",
		IpAddress: "54.192.47.26",
	},
	&Masquerade{
		Domain:    "accounts.hellocdn.net",
		IpAddress: "52.222.138.92",
	},
	&Masquerade{
		Domain:    "accounts.hellocdn.net",
		IpAddress: "13.32.5.154",
	},
	&Masquerade{
		Domain:    "accounts.hellocdn.net",
		IpAddress: "54.192.38.252",
	},
	&Masquerade{
		Domain:    "accounts.hellocdn.net",
		IpAddress: "54.192.13.68",
	},
	&Masquerade{
		Domain:    "accounts.hellocdn.net",
		IpAddress: "54.230.80.69",
	},
	&Masquerade{
		Domain:    "accounts.hellocdn.net",
		IpAddress: "52.222.140.92",
	},
	&Masquerade{
		Domain:    "accounts.hellocdn.net",
		IpAddress: "54.182.5.71",
	},
	&Masquerade{
		Domain:    "accounts.hellocdn.net",
		IpAddress: "54.230.28.44",
	},
	&Masquerade{
		Domain:    "accounts.hellocdn.net",
		IpAddress: "54.230.53.206",
	},
	&Masquerade{
		Domain:    "accounts.hellocdn.net",
		IpAddress: "13.32.23.130",
	},
	&Masquerade{
		Domain:    "accounts.hellocdn.net",
		IpAddress: "54.239.164.35",
	},
	&Masquerade{
		Domain:    "accounts.hellocdn.net",
		IpAddress: "54.230.18.10",
	},
	&Masquerade{
		Domain:    "accounts.hellocdn.net",
		IpAddress: "54.192.78.133",
	},
}
