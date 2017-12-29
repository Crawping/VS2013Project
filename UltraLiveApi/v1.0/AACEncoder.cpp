#include "Encoder.h"
#include "OperatNew.h"
#include "Error.h"

#ifdef OPERATOR_NEW
#define new OPERATOR_NEW
#pragma message("new(__FILE__,__LINE__)")
#endif

#include "faac.h"


//AAC is pretty good, I changed my  mind
class AACEncoder : public AudioEncoder
{
	UINT curBitRate;

	bool bFirstPacket;

	faacEncHandle faac;
	DWORD numReadSamples;
	DWORD outputSize;

	List<float> inputBuffer;

	List<BYTE>  aacBuffer;
	List<BYTE>  header;

	List<QWORD> bufferedTimestamps;
	QWORD curEncodeTimestamp;
	bool bFirstFrame;

	UINT SampleRate;
	UINT NumChannels;

public:
	AACEncoder(UINT bitRate, UINT sampleRate, UINT numChannels)
	{
		curBitRate = bitRate;
		SampleRate = sampleRate;
		NumChannels = numChannels;

		faac = faacEncOpen(sampleRate, numChannels, &numReadSamples, &outputSize);

		//Log(TEXT("numReadSamples: %d"), numReadSamples);
		aacBuffer.SetSize(outputSize + 2);
		aacBuffer[0] = 0xaf;
		aacBuffer[1] = 0x1;

		faacEncConfigurationPtr config = faacEncGetCurrentConfiguration(faac);
		config->bitRate = (bitRate * 1000) / numChannels;
		config->quantqual = 100;
		config->inputFormat = FAAC_INPUT_FLOAT;
		config->mpegVersion = MPEG4;
		config->aacObjectType = LOW;
		config->useLfe = 0;
		config->outputFormat = 0;

		int ret = faacEncSetConfiguration(faac, config);
		if (!ret)
			Log::writeError(LOG_RTSPSERV,1,"LiveSDK_Log:aac configuration failed");

		BYTE *tempHeader;
		DWORD len;

		header.SetSize(2);
		header[0] = 0xaf;
		header[1] = 0x00;

		faacEncGetDecoderSpecificInfo(faac, &tempHeader, &len);
		header.AppendArray(tempHeader, len);
		free(tempHeader);

		bFirstPacket = true;
		bFirstFrame = true;

// 		Log(TEXT("------------------------------------------"));
// 		Log(TEXT("%s"), GetInfoString().Array());
	}

	~AACEncoder()
	{
		faacEncClose(faac);
	}

	void SetFirstEnoder()
	{
		bFirstFrame = true;
		inputBuffer.Clear();
		bufferedTimestamps.Clear();
	}
	bool Encode(float *input, UINT numInputFrames, DataPacket &packet, QWORD &timestamp)
	{
		if (bFirstFrame)
		{
			curEncodeTimestamp = timestamp;
			bFirstFrame = false;
		}

		//------------------------------------------------

		QWORD curTimestamp = timestamp;

		UINT lastSampleSize = inputBuffer.Num();
		UINT numInputSamples = numInputFrames*NumChannels;
		if (NumChannels == 2)
			inputBuffer.AppendArray(input, numInputSamples);
		else
		{
			UINT inputBufferPos = inputBuffer.Num();
			inputBuffer.SetSize(inputBufferPos + numInputSamples);

			for (UINT i = 0; i < numInputSamples; i++)
			{
				UINT pos = i * 2;
				inputBuffer[inputBufferPos + i] = (input[pos] + input[pos + 1]) * 0.5f;
			}
		}

		int ret = 0;

		if (inputBuffer.Num() >= numReadSamples)
		{
			//now we have to upscale the floats.  fortunately we almost always have SSE
			UINT floatsLeft = numReadSamples;
			float *inputTemp = inputBuffer.Array();
			if ((UPARAM(inputTemp) & 0xF) == 0)
			{
				UINT alignedFloats = floatsLeft & 0xFFFFFFFC;

				for (UINT i = 0; i < alignedFloats; i += 4)
				{
					float *pos = inputTemp + i;
					_mm_store_ps(pos, _mm_mul_ps(_mm_load_ps(pos), _mm_set_ps1(32767.0f)));
				}

				floatsLeft &= 0x3;
				inputTemp += alignedFloats;
			}

			if (floatsLeft)
			{
				for (UINT i = 0; i<floatsLeft; i++)
					inputTemp[i] *= 32767.0f;
			}

			ret = faacEncEncode(faac, (int32_t*)inputBuffer.Array(), numReadSamples, aacBuffer.Array() + 2, outputSize);
			if (ret > 0)
			{
				if (bFirstPacket)
				{
					bFirstPacket = false;
					ret = 0;
				}
				else
				{
					packet.lpPacket = aacBuffer.Array();
					packet.size = ret + 2;

					timestamp = bufferedTimestamps[0];
					bufferedTimestamps.Remove(0);
				}
			}
			else if (ret < 0)
				AppWarning(TEXT("aac encode error"));

			inputBuffer.RemoveRange(0, numReadSamples);

			bufferedTimestamps << curEncodeTimestamp;
			curEncodeTimestamp = curTimestamp + (((numReadSamples - lastSampleSize) / NumChannels) * 1000 / SampleRate);
		}

		return ret > 0;
	}

	UINT GetFrameSize() const
	{
		return 1024;
	}

	void GetHeaders(DataPacket &packet)
	{
		packet.lpPacket = header.Array();
		packet.size = header.Num();
	}

	int GetBitRate() const { return curBitRate; }
	CTSTR GetCodec() const { return TEXT("AAC"); }

	String GetInfoString() const
	{
		String strInfo;
		strInfo << TEXT("Audio Encoding: AAC") <<
			TEXT("\r\n    bitrate: ") << IntString(curBitRate);

		return strInfo;
	}

	virtual int  GetsampleRate() const { return SampleRate; }
	virtual int  GetnumChannels() const { return NumChannels; }
};

AudioEncoder* CreateAACEncoder(UINT bitRate, UINT SampRate, UINT NumChannel)
{
	return new AACEncoder(bitRate, SampRate, NumChannel);
}