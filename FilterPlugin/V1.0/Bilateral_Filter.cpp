#include "Bilateral_Filter.h"

IMPLEMENT_DYNIC_FILTER(FilterBilateral, "˫���˲�", true)
FilterBilateral::FilterBilateral()
{
	RenderTarget = NULL;
	PixShader = NULL;
	width = 1280;
	hight = 720;
	BaseVideo = NULL;
	D3DRender = GetD3DRender();
}

FilterBilateral::~FilterBilateral()
{
	if (RenderTarget)
		delete RenderTarget;
	RenderTarget = NULL;

	if (PixShader)
		delete PixShader;
	PixShader = NULL;
}

bool FilterBilateral::InitFilter(UINT Width, UINT Height)
{
	Log::writeMessage(LOG_RTSPSERV, 1, "%s invoke begin! Width = %d,Height = %d", __FUNCTION__, Width, Height);

	PixShader = D3DRender->CreatePixelShaderFromFile(TEXT("shaders/Bilateral.pShader"));

	if (!PixShader)
	{
		Log::writeMessage(LOG_RTSPSERV, 1, "%s invoke end!CreatePixelShaderFromFile failed! shaders/Bilateral.pShader" __FUNCTION__);
		return false;
	}

	RenderTarget = D3DRender->CreateRenderTarget(Width, Height, GS_BGRA, FALSE);
	if (!RenderTarget)
	{
		Log::writeMessage(LOG_RTSPSERV, 1, "%s invoke end!CreateRenderTarget failed!" __FUNCTION__);
		return false;
	}
	width = Width;
	hight = Height;

	Log::writeMessage(LOG_RTSPSERV, 1, "%s invoke end!", __FUNCTION__);
	return true;
}

void FilterBilateral::GetDefaults(Value &JsonDefaults)
{

}

void FilterBilateral::UpDataSetting(Value &JsonDefaults)
{

}

Texture * FilterBilateral::GetRenderTarget()
{
	return RenderTarget;
}

void FilterBilateral::FilterRender(Texture *Target, const Vect2 &NewSize)
{
	if (Target && PixShader)
	{
		if (NewSize != Vect2(width, hight))
		{
			D3DRender->SetRenderTarget(NULL);

			if (RenderTarget)
			{
				delete RenderTarget;
			}
			width = NewSize.x;
			hight = NewSize.y;

			RenderTarget = D3DRender->CreateRenderTarget(width, hight, GS_BGRA, FALSE);

			D3DRender->SetRenderTarget(RenderTarget);
			D3DRender->ClearRenderTarget(0xFF000000);
		}

		D3DRender->LoadPixelShader(PixShader);

		D3DRender->DrawSprite(Target, 0xFFFFFFFF, 0.0f, 0.0f, width, hight);
	}
}
