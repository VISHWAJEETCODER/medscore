// Default avatar utility for user profiles
const avatarUtils = {
  // Default avatar options
  avatars: {
    male: [
      { id: 'male_1', name: 'Professional Male 1', url: '/assets/avatars/male_1.png' },
      { id: 'male_2', name: 'Professional Male 2', url: '/assets/avatars/male_2.png' },
      { id: 'male_3', name: 'Professional Male 3', url: '/assets/avatars/male_3.png' },
      { id: 'male_4', name: 'Professional Male 4', url: '/assets/avatars/male_4.png' }
    ],
    female: [
      { id: 'female_1', name: 'Professional Female 1', url: '/assets/avatars/female_1.png' },
      { id: 'female_2', name: 'Professional Female 2', url: '/assets/avatars/female_2.png' },
      { id: 'female_3', name: 'Professional Female 3', url: '/assets/avatars/female_3.png' },
      { id: 'female_4', name: 'Professional Female 4', url: '/assets/avatars/female_4.png' }
    ],
    neutral: [
      { id: 'neutral_1', name: 'Professional Neutral 1', url: '/assets/avatars/neutral_1.png' },
      { id: 'neutral_2', name: 'Professional Neutral 2', url: '/assets/avatars/neutral_2.png' },
      { id: 'neutral_3', name: 'Professional Neutral 3', url: '/assets/avatars/neutral_3.png' }
    ]
  },

  // Get all avatars
  getAllAvatars() {
    return {
      male: this.avatars.male,
      female: this.avatars.female,
      neutral: this.avatars.neutral
    };
  },

  // Get avatars by gender
  getAvatarsByGender(gender) {
    if (gender === 'male') return this.avatars.male;
    if (gender === 'female') return this.avatars.female;
    return this.avatars.neutral;
  },

  // Get random avatar by gender
  getRandomAvatar(gender = 'neutral') {
    const avatars = this.getAvatarsByGender(gender);
    const randomIndex = Math.floor(Math.random() * avatars.length);
    return avatars[randomIndex];
  },

  // Get avatar by ID
  getAvatarById(avatarId) {
    const allAvatars = [
      ...this.avatars.male,
      ...this.avatars.female,
      ...this.avatars.neutral
    ];
    return allAvatars.find(avatar => avatar.id === avatarId);
  },

  // Validate avatar ID
  isValidAvatarId(avatarId) {
    return this.getAvatarById(avatarId) !== undefined;
  },

  // Get default avatar for new user
  getDefaultAvatar(gender = 'neutral') {
    return this.getRandomAvatar(gender);
  },

  // Generate avatar URL
  generateAvatarUrl(avatarId) {
    const avatar = this.getAvatarById(avatarId);
    return avatar ? avatar.url : '/assets/avatars/default.png';
  }
};

module.exports = {
  avatarUtils
};
