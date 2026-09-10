import React, { useEffect, useRef, useState } from 'react';
// @ts-ignore
import translate from 'i18n-jsautotranslate';

export interface LanguageItem {
  value: string;
  label: string;
}

// Complete clean list of all 73 languages supported by client.edge
export const SUPPORTED_LANGUAGES: LanguageItem[] = [
  { value: 'english', label: 'English' },
  { value: 'afrikaans', label: 'Afrikaans' },
  { value: 'albanian', label: 'Albanian (Shqip)' },
  { value: 'amharic', label: 'Amharic (አማርኛ)' },
  { value: 'arabic', label: 'Arabic (العربية)' },
  { value: 'armenian', label: 'Armenian (Հայերեն)' },
  { value: 'azerbaijani', label: 'Azerbaijani (Azərbaycan)' },
  { value: 'bengali', label: 'Bengali (বাংলা)' },
  { value: 'bosnian', label: 'Bosnian (Bosanski)' },
  { value: 'bulgarian', label: 'Bulgarian (Български)' },
  { value: 'burmese', label: 'Burmese (မြန်မာ)' },
  { value: 'catalan', label: 'Catalan (Català)' },
  { value: 'chinese_simplified', label: 'Chinese Simplified (简体中文)' },
  { value: 'chinese_traditional', label: 'Chinese Traditional (繁體中文)' },
  { value: 'croatian', label: 'Croatian (Hrvatski)' },
  { value: 'czech', label: 'Czech (Čeština)' },
  { value: 'danish', label: 'Danish (Dansk)' },
  { value: 'deutsch', label: 'German (Deutsch)' },
  { value: 'dutch', label: 'Dutch (Nederlands)' },
  { value: 'estonian', label: 'Estonian (Eesti)' },
  { value: 'filipino', label: 'Filipino (Tagalog)' },
  { value: 'finnish', label: 'Finnish (Suomi)' },
  { value: 'french', label: 'French (Français)' },
  { value: 'greek', label: 'Greek (Ελληνικά)' },
  { value: 'gujarati', label: 'Gujarati (ગુજરાતી)' },
  { value: 'haitian_creole', label: 'Haitian Creole (Kreyòl)' },
  { value: 'hebrew', label: 'Hebrew (עברית)' },
  { value: 'hindi', label: 'Hindi (हिन्दी)' },
  { value: 'hungarian', label: 'Hungarian (Magyar)' },
  { value: 'icelandic', label: 'Icelandic (Íslenska)' },
  { value: 'indonesian', label: 'Indonesian (Bahasa Indonesia)' },
  { value: 'inuktitut', label: 'Inuktitut (ᐃᓄᒃᑎᑐᑦ)' },
  { value: 'irish', label: 'Irish (Gaeilge)' },
  { value: 'italian', label: 'Italian (Italiano)' },
  { value: 'japanese', label: 'Japanese (日本語)' },
  { value: 'kannada', label: 'Kannada (ಕನ್ನಡ)' },
  { value: 'khmer', label: 'Khmer (ភាសាខ្មែរ)' },
  { value: 'korean', label: 'Korean (한국어)' },
  { value: 'kurdish', label: 'Kurdish (Kurdî)' },
  { value: 'lao', label: 'Lao (ລາວ)' },
  { value: 'latvian', label: 'Latvian (Latviešu)' },
  { value: 'lithuanian', label: 'Lithuanian (Lietuvių)' },
  { value: 'malagasy', label: 'Malagasy' },
  { value: 'malay', label: 'Malay (Bahasa Melayu)' },
  { value: 'malayalam', label: 'Malayalam (മലയാളം)' },
  { value: 'maltese', label: 'Maltese (Malti)' },
  { value: 'maori', label: 'Maori (Te Reo Māori)' },
  { value: 'marathi', label: 'Marathi (मराठी)' },
  { value: 'nepali', label: 'Nepali (नेपाली)' },
  { value: 'norwegian', label: 'Norwegian (Norsk)' },
  { value: 'oriya', label: 'Oriya (ଓଡ଼ିଆ)' },
  { value: 'pashto', label: 'Pashto (پښتو)' },
  { value: 'persian', label: 'Persian (فارسی)' },
  { value: 'polish', label: 'Polish (Polski)' },
  { value: 'portuguese', label: 'Portuguese (Português)' },
  { value: 'punjabi', label: 'Punjabi (ਪੰਜਾਬੀ)' },
  { value: 'romanian', label: 'Romanian (Română)' },
  { value: 'russian', label: 'Russian (Русский)' },
  { value: 'samoan', label: 'Samoan (Gagana Samoa)' },
  { value: 'slovak', label: 'Slovak (Slovenčina)' },
  { value: 'slovene', label: 'Slovenian (Slovenščina)' },
  { value: 'spanish', label: 'Spanish (Español)' },
  { value: 'swahili', label: 'Swahili (Kiswahili)' },
  { value: 'swedish', label: 'Swedish (Svenska)' },
  { value: 'tamil', label: 'Tamil (தமிழ்)' },
  { value: 'telugu', label: 'Telugu (తెలుగు)' },
  { value: 'thai', label: 'Thai (ไทย)' },
  { value: 'tongan', label: 'Tongan (Lea Faka-Tonga)' },
  { value: 'turkish', label: 'Turkish (Türkçe)' },
  { value: 'ukrainian', label: 'Ukrainian (Українська)' },
  { value: 'urdu', label: 'Urdu (اردو)' },
  { value: 'vietnamese', label: 'Vietnamese (Tiếng Việt)' },
  { value: 'welsh', label: 'Welsh (Cymraeg)' }
];

export const LanguageSelector: React.FC = () => {
  const initialized = useRef(false);
  const [currentLanguage, setCurrentLanguage] = useState('english');

  useEffect(() => {
    // Explicitly disable translate.js from creating its own automatic select element
    if (translate.selectLanguageTag) {
      translate.selectLanguageTag.show = false;
    }

    if (initialized.current) return;
    initialized.current = true;

    try {
      // Use client-side edge translation service
      translate.service.use('client.edge');

      // Check if there's any active language in storage
      const savedLang = translate.storage ? translate.storage.get('to') : null;
      if (savedLang && savedLang !== 'english' && SUPPORTED_LANGUAGES.some((l) => l.value === savedLang)) {
        setCurrentLanguage(savedLang);
        translate.changeLanguage(savedLang);
        try {
          translate.execute();
        } catch {
          // Ignore execution error
        }
      }
    } catch (e) {
      console.warn('Translate initialization:', e);
    }

    // Periodically remove any rogue floating select injected by translate.js in bottom corner
    const purgeStraySelectors = () => {
      const stray = document.querySelectorAll(
        '#translateSelectLanguage, .translateSelectLanguage, select[id*="translateSelectLanguage"]'
      );
      stray.forEach((el) => {
        if (!el.closest('#main-language-selector')) {
          el.remove();
        }
      });
    };

    purgeStraySelectors();
    const interval = setInterval(purgeStraySelectors, 1500);

    return () => clearInterval(interval);
  }, []);

  const handleChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const lang = e.target.value;
    setCurrentLanguage(lang);

    if (lang === 'english') {
      try {
        // Reset DOM text back to the original authoring English
        translate.reset({ selectLanguageRefreshRender: false });
      } catch (err) {
        console.warn('Translate reset error:', err);
      }
      translate.changeLanguage('english');
    } else {
      translate.changeLanguage(lang);
      translate.execute();
    }
  };

  return (
    <div id="main-language-selector" className="flex flex-col items-center justify-center gap-0.5 min-w-[130px] ignore">
      <div className="min-h-[28px] flex items-center justify-center ignore">
        <select
          id="main-language-dropdown"
          value={currentLanguage}
          onChange={handleChange}
          aria-label="Select Language"
          className="bg-slate-800 text-slate-200 border border-slate-700 text-xs rounded px-2 py-1 focus:outline-none focus:border-indigo-500 cursor-pointer max-w-[140px] truncate ignore"
        >
          {SUPPORTED_LANGUAGES.map((lang) => (
            <option key={lang.value} value={lang.value} className="ignore">
              {lang.label}
            </option>
          ))}
        </select>
      </div>
      <a
        href="https://github.com/xnx3/translate"
        target="_blank"
        rel="noopener noreferrer"
        className="text-[9px] text-slate-500 hover:text-slate-400 transition-colors whitespace-nowrap ignore"
      >
        Powered by xnx3/translate
      </a>
    </div>
  );
};
