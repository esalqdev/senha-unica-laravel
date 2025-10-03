<?php

namespace Esalqdev\SenhaUnica;

use Illuminate\Support\ServiceProvider;

class SenhaUnicaServiceProvider extends ServiceProvider
{
    public function boot()
    {
        //
    }

    public function register()
    {
        // Mescla o config do pacote com o do app
        $this->mergeConfigFrom(
            __DIR__ . '/../config/senha_unica.php',
            'senha_unica'
        );

        // Registra o service para injeção de dependência
        $this->app->singleton(SenhaUnicaService::class, function ($app) {
            return new SenhaUnicaService(
                config('senha_unica.consumer_key'),
                config('senha_unica.consumer_secret'),
                config('senha_unica.base_url'),
                config('senha_unica.callback_id')
            );
        });
    }
}
