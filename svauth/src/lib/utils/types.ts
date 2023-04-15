interface OKResult<T> {
	ok: true;
	data: T;
}

interface ErrorResult {
	ok: false;
	error: string;
}

// Utility type to represent a result that can be either OK or an error
export type SafeResult<T> = OKResult<T> | ErrorResult;
