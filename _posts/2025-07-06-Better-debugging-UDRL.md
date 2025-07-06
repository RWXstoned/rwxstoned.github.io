---
title: Making the Debugging of UDRLs (a bit) Easier
subtitle: a simple addition to the UDRL-VS framework to enable the logging of debug strings in your loader at runtime 
thumbnail-img: "https://rwxstoned.github.io/assets/img/6/kr-pints.jpg"
---

The introduction of [this Visual Studio project](https://www.cobaltstrike.com/blog/revisiting-the-udrl-part-1-simplifying-development) as a template for building Cobalt Strike UDRL has come with a lot of little gimmicks aimed at making your life a bit easier as a malware developer. Developing Position Independant Code (PIC) is indeed extremely annoying and comes with a lot of constraints. To name one, the inability to define strings in a classic way. This project has made use of clever preprocessor macros to abstract away some of that pain, for instance with `PIC_STRING()` to define strings. Other useful features are `PRINT()`, the presence of a `Debug` build, etc. Please read the blog post above for more on this.

In my experience though, debugging your UDRL is still painful. Fundamentally, a piece of PIC code is NOT an executable. While the `Debug` build provided in the UDRL-VS Template is useful in certain scenarios, the .exe that it produces is not _exactly_ the UDRL that you will get in `Release` mode, and I found it more useful to debug the `Release` PIC blob in WinDbg rather than debugging the `Debug` executable produced.

![](https://rwxstoned.github.io/assets/img/6/kr-pints.jpg)


## Debug Strings

My debugging skills are fairly limited and mostly revolve around putting plenty of `printf("Here\n");` and `printf("Here2\n");`. But as a malware developer, in a lot of situations you do not have the luxury of a console to output statements. In the specific case of a UDRL, `printf()` is not readily available anyway.

If you compile your UDRL in `Debug` mode, you will end up with an executable, containing a `PRINT()` macro that you can enable to `printf()` to the console, but none of that is applicable in `Release` mode where all you generate is a PIC blob.

A substitute for printing an output to a console in such situations consist in using the [`OutputDebugString()` API](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-outputdebugstringw) to log something to WinDbg instead, where you'll hopefully be able to see your log if you have attached it to the process where you payload is running. In my case, these messages will most likely be even more `Here111`, `Here0` and `Here123`.

In fact, the Sleepmask-VS is leveraging that feature to provide that type of ability, if you define `ENABLE_LOGGING` ([here](https://github.com/Cobalt-Strike/sleepmask-vs/blob/main/sleepmask-vs/debug.h))

What you get is a `DLOGF()` macro as a wrapper around that API, which handles the annoying bits for you (variable number of args, formatted strings, etc...).

The UDRL-VS template does not define any such helper. Unfortunately, the `DLOGF` example is not directly usable because your UDRL cannot use traditional strings like this:

```
DLOG("I reached here \n");
```

Instead you must use something like this, in order to have everything on the `.text` section through the use of the nice `PIC_STRING` helper I mentionned above:

```
PIC_STRING(mystring, "I reached here \n"); //expands to constexpr char mystring[] {'I', ' ', 'r', 'e',... };
DLOG(mystring);
```

This is mildly annoying if we are going to have to type two lines for every print-statement we want to make.

You cannot wrap those two statements in a one-liner macro like this:

```
#define DLOGF(format, ...) PIC_STRING(mystring, format); DLOG(mystring)`
```

as this would end up redifining `mystring` on every invocation.

## Some Macro Magic

It turns out the `__LINE__` macro automatically expands to the line number where it is invoked. This can be used as a means to create a variable name which will be unique on each invocation, so that our macro does not end up trying to redefine the same `mystring` everytime it is used.

The following snippet shows how to define such a variable:

```
#define CONCAT(x,y) x ## y
#define EXPAND(x,y) CONCAT(x,y)
#define VARLINE(x) EXPAND(x, __LINE__)
```

Now `VARLINE(myvar)` will expand to `varline123` or `varline1337` or any unique name containing the line number. The second line may seem redundant but I found this was necessary to ensure that all macros were correctly expanded in the right order to end up with the intended result.

This may make things a bit clearer:

![](https://rwxstoned.github.io/assets/img/6/macrovar.png)

With the ability to create unique variable names in a macro, we can define a `DLOGF()` macro which will automatically unpack into something like what we desired above.

```
#define DLOGF(format, ...) PIC_STRING(); DLOG()
```

```
LOGF("I reached here \n");
```

will now indeed expand into those two lines:

```
PIC_STRING(mystring123, "I reached here \n"); 
DLOG(mystring123);
```

## The Code

The UDRL-VS is not open-source so I cannot directly share my version of the code but these are the snippets I amended.

I added the above macros in `Utils.h` to define our own `DLOGF`, which will expand to something that takes care of the `PIC_STRING` before calling `DLOG`:

```
#ifdef ENABLE_DEBUGSTRING
// this uses some Preprocessor Macro magic to essentially be able to use dlog
// with a PIC_STRING, which requires a new variable everytime, otherwise two invocations
// of DLOGF() will result in a variable redefinition.
// The solution here is to use __LINE__ to create a variable containing the line number,
// ensuring that each PIC_STRING relies on a unique variable name

#define CONCAT(x, y) × ## y 
#define EXPAND(x, y) CONCAT(x, y)
#define VARLINE(x) EXPAND(x, __LINE__)

// add the line number to x to create a unique name
#define DLOG(format, ...) dlog (format, _VA_ARGS__)
#define DLOGF(format, ...) PIC_STRING(VARLINE(myvar), format); DLOG(VARLINE(myvar), __VA_ARGS__)
void dlog(const char* format, ...);
#else
#define DLOG(format, ...);
#endif
```

`dlog()` is very similar to the Sleepmask-VS one I mentionned above. In this case though, we want to call `OutputDebugStringA`, so it resolves like this at runtime, in `Utils.cpp`:


```
#ifdef ENABLE_DEBUGSTRING
#include "FunctionResolving.h"

void dlog(const char* format, ...) {
	va_list arglist;
	va_start(arglist, format);
	char buff[1024];

	typedef int (WINAPI* VSPRINTF_S) (char*, size_t, const char*, va_list); typedef void (WINAPI* OUTPUTDEBUGSTRINGA) (LPCSTR);
	
	constexpr DWORD NTDLL_HASH = CompileTimeHash("ntdll.dll");
	constexpr DWORD KERNEL32_HASH = CompileTimeHash("kernel32.dll");
	constexpr DWORD sprintf_s_hash = CompileTimeHash("vsprintf_s");
	constexpr DWORD OutputDebugStringA_hash = CompileTimeHash("OutputDebugStringA");
	
	#ifdef _WIN64
		_PPEB pebAddress = (_PPEB) _readgsqword (0x60) ;
	#elif _WIN32
		_PPEB pebAddress = (_PPEB)__readfsdword(0x30);
	#endif

	VSPRINTF_S fnVsprintf_s = (VSPRINTF_S)GetProcAddressByHash(pebAddress, NTDLL_HASH, vsprintf_s_hash);
	OUTPUTDEBUGSTRINGA fnOutputDebugStringA = (OUTPUTDEBUGSTRINGA) GetProcAddressByHash(pebAddress, KERNEL32_HASH, OutputDebugStringA_hash);
	
	int len = fnVsprintf_s(buff, 1024, format, arglist);
	if (len > 0) {
		fnOutputDebugStringA(buff);
	}
	va_end (arglist);
}
#endif ENABLE_DEBUGSTRING
```

## Conclusion

You can now run your UDRL in its final form and observe it through WinDbg. This is what it looks like when printing out 3 statements such as below when looking at Notepad, where that UDRL has been injected:

`DLOGF("Test DLOGF: 0x%p\n", anInterestingAddress);`

![](https://rwxstoned.github.io/assets/img/6/debugstrings.png)

I find this option more comfortable than juggling with a `Debug` and a `Release` build and trying to then figure out why something that worked in one, does not anymore in the other !