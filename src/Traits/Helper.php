<?php

namespace Akaunting\Firewall\Traits;

use Akaunting\Firewall\Models\Log;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\IpUtils;

trait Helper
{
    public Request|string|array|null $request = null;
    public string|null $middleware = null;
    public int|null $user_id = null;

    public function isEnabled($middleware = null)
    {
        $middleware = $middleware ?? $this->middleware;

        return config('firewall.middleware.' . $middleware . '.enabled', config('firewall.enabled'));
    }

    public function isDisabled($middleware = null)
    {
        return ! $this->isEnabled($middleware);
    }

    public function isWhitelist()
    {
        return IpUtils::checkIp($this->ip(), config('firewall.whitelist'));
    }

    public function isMethod($middleware = null)
    {
        $middleware = $middleware ?? $this->middleware;

        if (! $methods = config('firewall.middleware.' . $middleware . '.methods')) {
            return false;
        }

        if (in_array('all', $methods)) {
            return true;
        }

        return in_array(strtolower($this->request->method()), $methods);
    }

    public function isRoute($middleware = null)
    {
        $middleware = $middleware ?? $this->middleware;

        if (! $routes = config('firewall.middleware.' . $middleware . '.routes')) {
            return false;
        }

        foreach ($routes['except'] as $ex) {
            if (! $this->request->is($ex)) {
                continue;
            }

            return true;
        }

        foreach ($routes['only'] as $on) {
            if ($this->request->is($on)) {
                continue;
            }

            return true;
        }

        return false;
    }

    public function isInput($name, $middleware = null)
    {
        $middleware = $middleware ?? $this->middleware;

        if (! $inputs = config('firewall.middleware.' . $middleware . '.inputs')) {
            return true;
        }

        if (! empty($inputs['only']) && ! in_array((string) $name, (array) $inputs['only'])) {
            return false;
        }

        return ! in_array((string) $name, (array) $inputs['except']);
    }

    public function log($middleware = null, $user_id = null, $level = 'medium')
    {
        $middleware = $middleware ?? $this->middleware;
        $user_id = $user_id ?? $this->user_id;

        $model = config('firewall.models.log', Log::class);

        $input = $this->request->input();

        foreach ((array) config('firewall.log.except') as $name) {
            if (array_key_exists($name, $input)) {
                $input[$name] = '******';
            }
        }

        $input = urldecode(http_build_query($input));
        $referrer = $this->utf8(mb_strcut((string) $this->request->server('HTTP_REFERER'), 0, 191));

        return $model::create([
            'ip' => $this->ip(),
            'level' => $level,
            'middleware' => $middleware,
            'user_id' => $user_id,
            'url' => $this->utf8((string) $this->request->fullUrl()),
            'referrer' => $referrer !== '' ? $referrer : null,
            'request' => $this->utf8(mb_strcut($input, 0, (int) config('firewall.log.max_request_size'))),
        ]);
    }

    /**
     * An attacker controls these bytes, and a strict utf8mb4 connection rejects a broken
     * sequence with SQLSTATE 22007. The write is what records the attempt and feeds the
     * auto-block counter, so losing it hands the caller a 500 and no trace at all.
     *
     * Cutting on a byte offset is what breaks the sequence: a multi-byte character split
     * in half leaves a dangling lead byte. urldecode() on the query string can also revive
     * raw bytes the client sent percent-encoded, which is why the whole value is filtered
     * and not only the truncated ones.
     */
    protected function utf8(string $value): string
    {
        return mb_convert_encoding($value, 'UTF-8', 'UTF-8');
    }

    public function ip()
    {
        return $this->request->ip();
    }
}
