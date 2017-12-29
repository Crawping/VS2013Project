#include "HTTPClient.h"
#include <winhttp.h>
#include "OperatNew.h"

#ifdef OPERATOR_NEW
#define new OPERATOR_NEW
#pragma message("new(__FILE__,__LINE__)")
#endif

BOOL HTTPGetFile (CTSTR url, CTSTR outputPath, CTSTR extraHeaders, int *responseCode)
{

    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    URL_COMPONENTS  urlComponents;
    BOOL secure = FALSE;
    BOOL ret = FALSE;

    String hostName, path;

    const TCHAR *acceptTypes[] = {
        TEXT("*/*"),
        NULL
    };

    hostName.SetLength(256);
    path.SetLength(1024);

    zero(&urlComponents, sizeof(urlComponents));

    urlComponents.dwStructSize = sizeof(urlComponents);
    
    urlComponents.lpszHostName = hostName;
    urlComponents.dwHostNameLength = hostName.Length();

    urlComponents.lpszUrlPath = path;
    urlComponents.dwUrlPathLength = path.Length();

    WinHttpCrackUrl(url, 0, 0, &urlComponents);

    if (urlComponents.nPort == 443)
        secure = TRUE;

    hSession = WinHttpOpen(L"User Agent", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession)
        goto failure;

	hConnect = WinHttpConnect(hSession, hostName, secure ? INTERNET_DEFAULT_HTTPS_PORT : urlComponents.nPort, 0);
    if (!hConnect)
        goto failure;

    hRequest = WinHttpOpenRequest(hConnect, TEXT("GET"), path, NULL, WINHTTP_NO_REFERER, acceptTypes, secure ? WINHTTP_FLAG_SECURE|WINHTTP_FLAG_REFRESH : WINHTTP_FLAG_REFRESH);
    if (!hRequest)
        goto failure;

    BOOL bResults = WinHttpSendRequest(hRequest, extraHeaders, extraHeaders ? -1 : 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);

    // End the request.
    if (bResults)
        bResults = WinHttpReceiveResponse(hRequest, NULL);
    else
        goto failure;

    TCHAR statusCode[8];
    DWORD statusCodeLen;

    statusCodeLen = sizeof(statusCode);
    if (!WinHttpQueryHeaders (hRequest, WINHTTP_QUERY_STATUS_CODE, WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusCodeLen, WINHTTP_NO_HEADER_INDEX))
        goto failure;

    *responseCode = wcstoul(statusCode, NULL, 10);

    if (bResults && *responseCode == 200)
    {
        BYTE buffer[16384];
        DWORD dwSize, dwOutSize;

        XFile updateFile;

        if (!updateFile.Open(outputPath, XFILE_WRITE, CREATE_ALWAYS))
            goto failure;

        do 
        {
            // Check for available data.
            dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
                goto failure;

            if (!WinHttpReadData(hRequest, (LPVOID)buffer, dwSize, &dwOutSize))
            {
                goto failure;
            }
            else
            {
                if (!dwOutSize)
                    break;

                if (!updateFile.Write(buffer, dwOutSize))
                    goto failure;
            }
        } while (dwSize > 0);

        updateFile.Close();
    }

    ret = TRUE;

failure:
    if (hSession)
        WinHttpCloseHandle(hSession);
    if (hConnect)
        WinHttpCloseHandle(hConnect);
    if (hRequest)
        WinHttpCloseHandle(hRequest);

    return ret;
}

DWORD HTTPPostFile(String url, char * outHtml, unsigned &bufeLen, char *pPost, int nPostLen, CTSTR extraHeaders, int *responseCode)
{
	if (NULL == outHtml || 0 == bufeLen)
	{
		return 1;
	}
	unsigned nMaxBufLen = bufeLen;
	bufeLen = 0;
	HINTERNET hSession = NULL;
	HINTERNET hConnect = NULL;
	HINTERNET hRequest = NULL;
	URL_COMPONENTS  urlComponents;
	BOOL secure = FALSE;
	DWORD ret   = 1;

	String hostName, path;

	const TCHAR *acceptTypes[] = {
		TEXT("*/*"),
		NULL
	};

	hostName.SetLength(256);
	path.SetLength(1024);

	zero(&urlComponents, sizeof(urlComponents));

	urlComponents.dwStructSize = sizeof(urlComponents);

	urlComponents.lpszHostName = hostName;
	urlComponents.dwHostNameLength = hostName.Length();

	urlComponents.lpszUrlPath = path;
	urlComponents.dwUrlPathLength = path.Length();

	WinHttpCrackUrl(url, 0, 0, &urlComponents);

	if (urlComponents.nPort == 443)
		secure = TRUE;

	hSession = WinHttpOpen(TEXT("ButelLive agent"), WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
	if (!hSession)
		goto failure;

	DWORD dwTimeOut = 5000; // ms
	DWORD dwSize = sizeof(DWORD);
	WinHttpSetOption(hSession, WINHTTP_OPTION_CONNECT_TIMEOUT, &dwTimeOut, dwSize);
	WinHttpSetOption(hSession, WINHTTP_OPTION_SEND_TIMEOUT, &dwTimeOut, dwSize);
	WinHttpSetOption(hSession, WINHTTP_OPTION_RECEIVE_TIMEOUT, &dwTimeOut, dwSize);

	hConnect = WinHttpConnect(hSession, hostName, urlComponents.nPort, 0);
	if (!hConnect)
		goto failure;	

	hRequest = WinHttpOpenRequest(hConnect, TEXT("Post"), path, NULL, WINHTTP_NO_REFERER, acceptTypes, secure ? WINHTTP_FLAG_SECURE | WINHTTP_FLAG_REFRESH : WINHTTP_FLAG_REFRESH);
	if (!hRequest)
		goto failure;	

	
	BOOL bResults = WinHttpSendRequest(
		hRequest, 
		extraHeaders, 
		extraHeaders ? -1 : 0,		
		(LPVOID)pPost,
		nPostLen,
		nPostLen,
		NULL
		);

	// End the request.
	if (bResults)
		bResults = WinHttpReceiveResponse(hRequest, NULL);
	else
		goto failure;

	TCHAR statusCode[8];
	DWORD statusCodeLen;

	statusCodeLen = sizeof(statusCode);
	if (!WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE, WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusCodeLen, WINHTTP_NO_HEADER_INDEX))
		goto failure;

	*responseCode = wcstoul(statusCode, NULL, 10);

	if (bResults && *responseCode == 200)
	{
		BYTE buffer[16384];
		DWORD dwSize, dwOutSize;
		do
		{
			// Check for available data.
			dwSize = 0;
			if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
				goto failure;

			if (!WinHttpReadData(hRequest, (LPVOID)buffer, dwSize, &dwOutSize))
			{
				goto failure;
			}
			else
			{
				if (!dwOutSize)
					break;	

				if (bufeLen + dwOutSize > nMaxBufLen)
				{
					goto failure;
				}
				//strHtml.AppendString((CTSTR)buffer, dwOutSize);
				memcpy(outHtml + bufeLen, buffer, dwOutSize);
				bufeLen += dwOutSize;
				outHtml[bufeLen] = '\0';
			}
		} while (dwSize > 0);		
	}
	ret = 0;

failure:
	if (0 != ret)
	{
		DWORD dwError = GetLastError();
		if (dwError != 0)
		{
			ret = dwError;
		}
	}
	
	if (hSession)
		WinHttpCloseHandle(hSession);
	if (hConnect)
		WinHttpCloseHandle(hConnect);
	if (hRequest)
		WinHttpCloseHandle(hRequest);

	return ret;
}

DWORD HTTPGetFile(String url, char * outHtml, unsigned &bufeLen, CTSTR extraHeaders, int *responseCode)
{
	if (NULL == outHtml || 0 == bufeLen)
	{
		return 1;
	}
	unsigned nMaxBufLen = bufeLen;
	bufeLen = 0;
	HINTERNET hSession = NULL;
	HINTERNET hConnect = NULL;
	HINTERNET hRequest = NULL;
	URL_COMPONENTS  urlComponents;
	BOOL secure = FALSE;
	DWORD ret = 1;

	String hostName, path;

	const TCHAR *acceptTypes[] = {
		TEXT("*/*"),
		NULL
	};

	hostName.SetLength(256);
	path.SetLength(1024);

	zero(&urlComponents, sizeof(urlComponents));

	urlComponents.dwStructSize = sizeof(urlComponents);

	urlComponents.lpszHostName = hostName;
	urlComponents.dwHostNameLength = hostName.Length();

	urlComponents.lpszUrlPath = path;
	urlComponents.dwUrlPathLength = path.Length();

	WinHttpCrackUrl(url, 0, 0, &urlComponents);

	if (urlComponents.nPort == 443)
		secure = TRUE;

	hSession = WinHttpOpen(TEXT("ButelLive agent"), WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
	if (!hSession)
		goto failure;

	DWORD dwTimeOut = 5000; // ms
	DWORD dwSize = sizeof(DWORD);
	WinHttpSetOption(hSession, WINHTTP_OPTION_CONNECT_TIMEOUT, &dwTimeOut, dwSize);
	WinHttpSetOption(hSession, WINHTTP_OPTION_SEND_TIMEOUT, &dwTimeOut, dwSize);
	WinHttpSetOption(hSession, WINHTTP_OPTION_RECEIVE_TIMEOUT, &dwTimeOut, dwSize);

	hConnect = WinHttpConnect(hSession, hostName, urlComponents.nPort, 0);
	if (!hConnect)
		goto failure;

	hRequest = WinHttpOpenRequest(hConnect, TEXT("Get"), path, NULL, WINHTTP_NO_REFERER, acceptTypes, secure ? WINHTTP_FLAG_SECURE | WINHTTP_FLAG_REFRESH : WINHTTP_FLAG_REFRESH);
	if (!hRequest)
		goto failure;


	BOOL bResults = WinHttpSendRequest(
		hRequest,
		extraHeaders,
		extraHeaders ? -1 : 0,
		NULL,
		0,
		0,
		NULL
		);

	// End the request.
	if (bResults)
		bResults = WinHttpReceiveResponse(hRequest, NULL);
	else
		goto failure;

	TCHAR statusCode[8];
	DWORD statusCodeLen;

	statusCodeLen = sizeof(statusCode);
	if (!WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE, WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusCodeLen, WINHTTP_NO_HEADER_INDEX))
	{
		//ERROR_WINHTTP_HEADER_NOT_FOUND
		int error = GetLastError();
		goto failure;
	}

	*responseCode = wcstoul(statusCode, NULL, 10);

	if (bResults && *responseCode == 200)
	{
		BYTE buffer[16384];
		DWORD dwSize, dwOutSize;
		do
		{
			// Check for available data.
			dwSize = 0;
			if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
				goto failure;

			if (!WinHttpReadData(hRequest, (LPVOID)buffer, dwSize, &dwOutSize))
			{
				goto failure;
			}
			else
			{
				if (!dwOutSize)
					break;

				if (bufeLen + dwOutSize > nMaxBufLen)
				{
					goto failure;
				}
				//strHtml.AppendString((CTSTR)buffer, dwOutSize);
				memcpy(outHtml + bufeLen, buffer, dwOutSize);
				bufeLen += dwOutSize;
				outHtml[bufeLen] = '\0';
			}
		} while (dwSize > 0);
	}
	ret = 0;

failure:
	if (0 != ret)
	{
		DWORD dwError = GetLastError();
		if (dwError != 0)
		{
			ret = dwError;
		}
	}

	if (hSession)
		WinHttpCloseHandle(hSession);
	if (hConnect)
		WinHttpCloseHandle(hConnect);
	if (hRequest)
		WinHttpCloseHandle(hRequest);

	return ret;
}
String HTTPGetString (CTSTR url, CTSTR extraHeaders, int *responseCode)
{
    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    URL_COMPONENTS  urlComponents;
    BOOL secure = FALSE;
	String result = "";

    String hostName, path;

    const TCHAR *acceptTypes[] = {
        TEXT("*/*"),
        NULL
    };

    hostName.SetLength(256);
    path.SetLength(1024);

    zero(&urlComponents, sizeof(urlComponents));

    urlComponents.dwStructSize = sizeof(urlComponents);
    
    urlComponents.lpszHostName = hostName;
    urlComponents.dwHostNameLength = hostName.Length();

    urlComponents.lpszUrlPath = path;
    urlComponents.dwUrlPathLength = path.Length();

    WinHttpCrackUrl(url, 0, 0, &urlComponents);

    if (urlComponents.nPort == 443)
        secure = TRUE;

    hSession = WinHttpOpen(TEXT("Blive"), WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
	if (!hSession)
	{
		DWORD error = GetLastError();
		goto failure;
	}        

	hConnect = WinHttpConnect(hSession, hostName, urlComponents.nPort, 0);
    if (!hConnect)
        goto failure;

    hRequest = WinHttpOpenRequest(hConnect, TEXT("GET"), path, NULL, WINHTTP_NO_REFERER, acceptTypes, secure ? WINHTTP_FLAG_SECURE|WINHTTP_FLAG_REFRESH : WINHTTP_FLAG_REFRESH);
    if (!hRequest)
        goto failure;

    BOOL bResults = WinHttpSendRequest(hRequest, extraHeaders, extraHeaders ? -1 : 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);

    // End the request.
    if (bResults)
        bResults = WinHttpReceiveResponse(hRequest, NULL);
	else
	{
		DWORD error = GetLastError();
		goto failure;
	}
        

    TCHAR statusCode[8];
    DWORD statusCodeLen;

    statusCodeLen = sizeof(statusCode);
    if (!WinHttpQueryHeaders (hRequest, WINHTTP_QUERY_STATUS_CODE, WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusCodeLen, WINHTTP_NO_HEADER_INDEX))
        goto failure;

    *responseCode = wcstoul(statusCode, NULL, 10);	

    if (bResults && *responseCode == 200)
    {
        CHAR buffer[16384];
        DWORD dwSize, dwOutSize;

        do 
        {
            // Check for available data.
            dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
                goto failure;

            if (!WinHttpReadData(hRequest, (LPVOID)buffer, dwSize, &dwOutSize))
            {
                goto failure;
            }
            else
            {
                if (!dwOutSize)
                    break;

				// Ensure the string is terminated.
				buffer[dwOutSize] = 0;

				String b = String((LPCSTR)buffer);
				result.AppendString(b);
            }
        } while (dwSize > 0);
    }

failure:
    if (hSession)
        WinHttpCloseHandle(hSession);
    if (hConnect)
        WinHttpCloseHandle(hConnect);
    if (hRequest)
        WinHttpCloseHandle(hRequest);

    return result;
}


String CreateHTTPURL(String host, String path, String extra, bool secure)
{
    URL_COMPONENTS components = {
        sizeof URL_COMPONENTS,
        secure ? L"https" : L"http",
        secure ? 5 : 4,
        secure ? INTERNET_SCHEME_HTTPS : INTERNET_SCHEME_HTTP,
        host.Array(), host.Length(),
        secure ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT,
        nullptr, 0,
        nullptr, 0,
        path.Array(), path.Length(),
        extra.Array(), extra.Length()
    };

    String url;
    url.SetLength(MAX_PATH);
    DWORD length = MAX_PATH;
    if (!WinHttpCreateUrl(&components, ICU_ESCAPE, url.Array(), &length))
        return String();

    url.SetLength(length);
    return url;
}