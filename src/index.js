import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure';
import { nip19, nip98 } from 'nostr-tools';
import { readServerConfig, uploadFile, validateServerConfiguration } from 'nostr-tools/nip96';
import { sha256 } from '@noble/hashes/sha256'
import { base64 } from '@scure/base'

async function hashFile(file) {
	let payloadBytes = new Uint8Array();
	let fileStream = file.stream();
	let reader = fileStream.getReader();

	try {
		while (true) {
			let { done, value } = await reader.read();

			if (done) {
				break;
			}

			let oldPayload = payloadBytes;
			payloadBytes = new Uint8Array(oldPayload.length + value.length);

			payloadBytes.set(oldPayload, 0);
			payloadBytes.set(value, oldPayload.length);
		}
	} finally {
		reader.releaseLock();
	}

	let hash = sha256(payloadBytes);
	return base64.encode(hash);
}

// Stolen directly from nostr-tools and modified slightly
// vs nostr-tools
// Hashes the payload properly(?) and encodes it with base64 rather than hex (per nip-96 rather than nip-98)

async function myNip96and98ishToken(
  loginUrl,
  httpMethod,
  sign,
  includeAuthorizationScheme,
  payload
) {
  const event = {
    kind: 27235,
    tags: [
      ['u', loginUrl],
      ['method', httpMethod],
    ],
    created_at: Math.round(new Date().getTime() / 1000),
    content: '',
  }

  if (payload) {
    event.tags.push(['payload', await hashFile(payload)])
  }

  const signedEvent = await sign(event)

  return "Nostr " + base64.encode(new TextEncoder().encode(JSON.stringify(signedEvent)))
}

// Stolen directly from nostr-tools and modified slightly
async function myUploadFile(
  file,
  serverApiUrl,
  nip98AuthorizationHeader,
  optionalFormDataFields,
) {
  // Create FormData object
  const formData = new FormData()

  // Append the authorization header to HTML Form Data
  //formData.append('Authorization', nip98AuthorizationHeader)

  // Append optional fields to FormData
  optionalFormDataFields &&
    Object.entries(optionalFormDataFields).forEach(([key, value]) => {
      if (value) {
        formData.append(key, value)
      }
    })

  // Append the file to FormData as the last field
  formData.append('file', file)

  // Make the POST request to the server
  const response = await fetch(serverApiUrl, {
    method: 'POST',
    headers: {
      Authorization: nip98AuthorizationHeader,
      'Content-Type': 'multipart/form-data',
    },
    body: formData,
  })

  if (response.ok === false) {
    // 413 Payload Too Large
    if (response.status === 413) {
      throw new Error('File too large!')
    }

    // 400 Bad Request
    if (response.status === 400) {
      throw new Error('Bad request! Some fields are missing or invalid!')
    }

    // 403 Forbidden
    if (response.status === 403) {
      throw new Error('Forbidden! Payload tag does not match the requested file!')
    }

    // 402 Payment Required
    if (response.status === 402) {
      throw new Error('Payment required!')
    }

    // unknown error
    throw new Error('Unknown error in uploading file!')
  }

  try {
    const parsedResponse = await response.json()

    if (!validateFileUploadResponse(parsedResponse)) {
      throw new Error('Invalid response from the server!')
    }

    return parsedResponse
  } catch (error) {
    throw new Error('Error parsing JSON response!')
  }
}

async function doUpload(serverBase, privateKey, file, myVersion) {
	let noTransform = false;

	let urlRegex = /^http(s?):\/\//;

	let server = await readServerConfig(serverBase);

	if (!validateServerConfiguration(server)) {
		throw Error(`Invalid server config ${server}`);
	}

	let apiUrl = server.api_url;
	if (urlRegex.exec(apiUrl) === null) {
		apiUrl = `${serverBase}${apiUrl}`;
	}

	let auth;
	if (!myVersion) {
		auth = await nip98.getToken(
			apiUrl, "POST",
			async (e) => {
				return await finalizeEvent(e, privateKey);
			},
			true,
			file
		);
	} else {
		auth = await myNip96and98ishToken(
			apiUrl, "POST",
			async (e) => {
				return await finalizeEvent(e, privateKey);
			},
			true,
			file
		);
	}

	let uploadOptions = {
		size: file.size,
	};

	console.log(`File type: ${file.type}`);
	if (file.type) {
		//file.content_type = file.type;
	}

	if (noTransform) {
		uploadOptions.no_transform = true;
	}

	let response;
	if (!myVersion) {
		response = await uploadFile(
			file,
			apiUrl, auth,
			uploadOptions
		);
	} else {
		response = await myUploadFile(
			file,
			apiUrl, auth,
			uploadOptions
		);
	}

	console.log(`File type: ${response}`);

	return response;
}

(() => {
	let nsecInput = document.getElementById("nsec");
	let hostInput = document.getElementById("nip96-host");
	let fileInput = document.getElementById("file-upload");
	let messageElement = document.getElementById("message");
	let uploadButton = document.getElementById("upload");
	let myVersionCheckbox = document.getElementById("my-version");

	nsecInput.value = nip19.nsecEncode(generateSecretKey());
	uploadButton.addEventListener("click", async (event) => {
		messageElement.textContent = "uploading...";
		let nsec = nip19.decode(nsecInput.value);

		// Not going to handle errors here

		let nip96HostUrl = hostInput.value;
		for (var file of fileInput.files) {
			try
			{
				let response = await doUpload(nip96HostUrl, nsec.data, file, myVersionCheckbox.checked);
				console.log(response);

				messageElement.style.removeProperty("color");
				messageElement.textContent = "ding, fries are done. Check console for details.";
			} catch (e) {
				console.log(e);
				console.log(`Response Body:\n${e.responseBody}`);
				messageElement.style.color = "red";
				messageElement.textContent = "ding, fries are done. error.";
			}
		}
	});
})();
