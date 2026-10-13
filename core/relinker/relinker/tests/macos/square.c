#include <stddef.h>
#include <stdint.h>

char *getenv(const char *name);
void exit(int status);
void _Exit(int status);
int puts(const char *text);
int sceVideoOutOpen(int userId, int busType, int index, const void *param);
void sceVideoOutSetBufferAttribute2(void *attribute, uint64_t pixelFormat, uint32_t tilingMode, uint32_t width, uint32_t height, uint64_t option, uint32_t dccControl, uint64_t dccClear);
int sceVideoOutRegisterBuffers2(int handle, int setIndex, int bufferIndexStart, const void *buffers, int bufferNum, const void *attribute, int category, void *option);
int sceVideoOutSubmitFlip(int handle, int index, int flipMode, int64_t flipArg);
int sceVideoOutWaitVblank(int handle);
int scePadInit(void);
int scePadOpen(int userId, int type, int index, const void *param);
int scePadRead(int handle, void *data, int count);
int sceAudioOutOpen(int userId, int type, int index, uint32_t len, uint32_t freq, uint32_t param);
int sceAudioOutOutput(int handle, const void *ptr);

enum { SquareWidth = 320, SquareHeight = 180, SquareSize = 28, SquareFramesDefault = 180 };

static _Alignas(65536) uint8_t square_pixels[262144];

struct SquareBuffers {
    const void *data;
    const void *metadata;
    const void *reserved0;
    const void *reserved1;
};

static int square_frames(const char *text) {
    int value = 0;
    if (text == 0 || *text == 0) return SquareFramesDefault;
    while (*text >= '0' && *text <= '9') {
        value = value * 10 + (*text - '0');
        ++text;
    }
    return value > 0 ? value : SquareFramesDefault;
}

static void paint(uint8_t *pixels, int originX, int originY) {
    int y;
    for (y = 0; y < SquareHeight; ++y) {
        int x;
        for (x = 0; x < SquareWidth; ++x) {
            uint8_t *pixel = pixels + ((size_t)y * SquareWidth + (size_t)x) * 4u;
            int inside = x >= originX && x < originX + SquareSize && y >= originY && y < originY + SquareSize;
            pixel[0] = inside ? 0x40 : 0x20;
            pixel[1] = inside ? 0xe0 : 0x18;
            pixel[2] = inside ? 0x40 : 0x10;
            pixel[3] = 0xff;
        }
    }
}

static void tone(int16_t *samples) {
    int index;
    for (index = 0; index < 256; ++index) {
        int16_t sample = (index & 16) != 0 ? 4000 : -4000;
        samples[index * 2] = sample;
        samples[index * 2 + 1] = sample;
    }
}

void guest_start(void *stack, void *unused) {
    uint8_t *pixels = square_pixels;
    struct SquareBuffers buffers;
    unsigned char attribute[128];
    unsigned char padData[256];
    int16_t samples[512];
    int frames;
    int video;
    int pad;
    int audio;
    int x = 40;
    int y = 30;
    int dx = 3;
    int dy = 2;
    int frame;
    int index;
    (void)stack;
    (void)unused;
    frames = square_frames(getenv("APS5_SQUARE_FRAMES"));
    buffers.data = pixels;
    buffers.metadata = 0;
    buffers.reserved0 = 0;
    buffers.reserved1 = 0;
    for (index = 0; index < 128; ++index) attribute[index] = 0;
    for (index = 0; index < 256; ++index) padData[index] = 0;
    video = sceVideoOutOpen(255, 0, 0, 0);
    if (video < 0) {
        puts("square video open failed");
        exit(1);
    }
    sceVideoOutSetBufferAttribute2(attribute, 0x8000000000000000ull, 1, SquareWidth, SquareHeight, 0, 0, 0);
    if (sceVideoOutRegisterBuffers2(video, 0, 0, &buffers, 1, attribute, 0, 0) != 0) {
        puts("square register failed");
        exit(1);
    }
    pad = scePadInit() == 0 ? scePadOpen(255, 0, 0, 0) : -1;
    audio = sceAudioOutOpen(255, 0, 0, 256, 48000, 1);
    for (frame = 0; frame < frames; ++frame) {
        if (pad >= 0 && scePadRead(pad, padData, 1) > 0) {
            int stickX = padData[4];
            int stickY = padData[5];
            if (stickX < 100) dx = -3;
            else if (stickX > 156) dx = 3;
            if (stickY < 100) dy = -2;
            else if (stickY > 156) dy = 2;
        }
        paint(pixels, x, y);
        if (sceVideoOutSubmitFlip(video, 0, 1, frame) != 0) {
            puts("square flip failed");
            exit(1);
        }
        sceVideoOutWaitVblank(video);
        if (audio > 0 && (frame % 15) == 0) {
            tone(samples);
            sceAudioOutOutput(audio, samples);
        }
        x += dx;
        y += dy;
        if (x < 0 || x > SquareWidth - SquareSize) {
            dx = -dx;
            x += dx;
        }
        if (y < 0 || y > SquareHeight - SquareSize) {
            dy = -dy;
            y += dy;
        }
    }
    puts("square presented");
    _Exit(0);
}
